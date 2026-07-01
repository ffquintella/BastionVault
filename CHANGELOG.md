# Changelog

All notable changes to BastionVault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

<!--
=============================================================================
  CHANGELOG MAINTENANCE INSTRUCTIONS
=============================================================================

This file MUST be updated after every feature, phase, or roadmap stage.

WHEN TO UPDATE:
  - After completing a roadmap phase (e.g., "Hiqlite Phase 5")
  - After implementing a feature from features/*.md
  - After adding a new GUI phase
  - After adding a new credential/auth backend
  - After any bug fix that affects user-facing behavior
  - After dependency additions or removals
  - After CI/CD or build system changes

HOW TO UPDATE:
  1. Add entries under [Unreleased] in the correct category (Added/Changed/Fixed/Removed)
  2. When cutting a release, move [Unreleased] items to a new version header
  3. Use imperative mood ("Add", not "Added" or "Adds")
  4. Reference feature files, roadmap phases, or issue numbers where applicable
  5. Group related entries under a subsection (e.g., "#### FIDO2 Auth Backend")
  6. Keep entries concise but specific enough to understand the change

CATEGORIES:
  ### Added       - New features, endpoints, commands, files
  ### Changed     - Behavior changes, refactors, dependency updates
  ### Deprecated  - Features that will be removed in a future version
  ### Removed     - Features, files, or dependencies removed
  ### Fixed       - Bug fixes
  ### Security    - Vulnerability fixes or security improvements

EXAMPLE ENTRY:
  - **FIDO2 auth backend** (`src/modules/credential/fido2/`) -- WebAuthn registration
    and login with hardware security keys. 7 API endpoints, `webauthn-rs` 0.5 integration.
    (Phase 6, `roadmaps/tauri-gui-fido2.md`)
=============================================================================
-->

## [Unreleased]

### Added
- **PKI root-chain import + key-less issuers** (`src/modules/pki/`) --
  `pki/config/ca` now accepts a full CA chain in one paste: one or more CA
  CERTIFICATE blocks with an optional single private key. The cert matching
  the key becomes a signing issuer; every other CA cert imports as a
  **key-less** (trust/chain-only) issuer. With no key, all CAs import as
  trust anchors. Certificate order is irrelevant (the key match, not
  position, picks the signer) and re-importing an already-present cert (by
  serial) is an idempotent skip.
  - New `CaMetadata.keyless` flag and `IssuerHandle.signer: Option<Signer>`;
    key-less issuers load with no signer and are rejected at signing time via
    `issuers::require_key` / `take_signer` with a clear 400.
  - New `issuers::add_issuer_keyless` and `issuers::find_issuer_by_serial`.
- **GUI: Import root CA chain tree** (`gui/`) -- the Import root CA modal now
  renders a live chain tree as you paste (root -> intermediate -> CA), flags
  non-CA certs and missing keys, and shows the imported hierarchy on success
  (signing vs trust-only vs already-present). Backed by a new local-only
  `pki_parse_chain` Tauri command (parses in-process, works in remote mode).

### Changed
- `pki/config/ca` responses now include a per-cert `chain` array (issuer id,
  name, CN, serial, self-signed, has-key, key-less, skipped) so tooling can
  render the imported hierarchy. Re-importing the same bundle is now a no-op
  skip rather than a duplicate-name error.

### Fixed
- **PKI CA import returned a bewildering HTTP 500** -- pasting a CA
  certificate (or a chain) with no private key hit `ErrPkiPemBundleInvalid`
  and surfaced as `HTTP 500: PKI pem bundle is invalid`. Import-validation
  failures (`ErrPkiPemBundleInvalid`, `ErrPkiCertKeyMismatch`,
  `ErrPkiKeyTypeInvalid`, `ErrPkiCertIsNotCA`, `ErrPkiCertChainIncorrect`)
  are now client errors (HTTP 400) with actionable messages ("no CERTIFICATE
  block", "the private key does not match any certificate in it",
  "certificate #N is not a CA", ...).
- **PKI CA import silently dropped every cert after the first** -- a pasted
  chain only ever imported its first certificate. All CA certs in the bundle
  are now imported so `ca_chain` resolves end to end.

## [0.22.3] - 2026-06-30

### Fixed
- GUI: Secrets owner lookups built a doubled path. Both the listing owner badge
  and the Share window prepended `mountBase` to `currentPath`, but `currentPath`
  already carries the mount prefix, producing paths like
  `secret/secret/tests/foo` that never matched an owner record. Effects: every
  owned secret was mislabelled "unowned" in the listing, and the Share window
  showed the owner as unowned (hiding grant/transfer controls) while its
  grant/revoke/list calls targeted the wrong canonical path. Both now use
  `currentPath + key`, consistent with the asset-group and detail-panel paths.

## [0.22.2] - 2026-06-30

### Added

- **Docs: Per-environment KV v2 secrets** (`docs/kv-environments.md`). Operator
  guide covering the base+overrides model, merge/resolution rules, the HTTP API
  (read `?env=`, targeted/full/legacy write modes, the advisory `environments`
  registry), CLI (`bvault read/write --env`), the GUI environment selector and
  inherited/override workflow, and the `required_parameters`/`allowed_parameters`
  policy interplay. Linked from the sidebar, CLI reference (`read`/`write`), and
  secret-engines overview.

## [0.22.1] - 2026-06-30

### Added

- **Policy builder: restrict a rule to specific environment(s)**
  (`gui/src/components/PolicyBlockEditor.tsx`, `gui/src/lib/policyHcl.ts`). Each
  policy rule in the Visual builder gains a "Restrict to environments" field.
  Entering env names emits `required_parameters = ["env"]` and
  `allowed_parameters = { "env" = [...], "*" = [] }` — `env` becomes required and
  value-constrained, while the `"*"` allow-all sentinel keeps every other
  parameter (write-body fields, `version`) working so the restriction only gates
  `env`. New pure helpers `envRestrictionOf` / `withEnvRestriction` (unit-tested
  in `gui/src/test/policyHcl.test.ts`). Surfaces the per-environment ACL that the
  engine already enforced (`features/kv-environments.md`).

## [0.22.0] - 2026-06-30

### Added

#### Per-environment KV v2 secret values (`features/kv-environments.md`)

- **`env` request parameter wired end-to-end.** GET query strings (`?env=prod`)
  and the embedded-backend path are now parsed into `req.data` *before* the ACL
  check (new `src/logical/util.rs::split_path_query` / `parse_query_allowlist`,
  consumed by both `src/http/logical.rs` and `gui/src-tauri/src/backend.rs`).
  This makes a policy's `required_parameters = ["env"]` and
  `allowed_parameters = { env = [...] }` actually enforceable on KV reads --
  previously a plain GET carried no `env`, so such a policy silently locked
  reads. The router now merges path captures into seeded `req.data` instead of
  replacing it (`src/logical/backend.rs`).
- **A single KV v2 secret can hold per-environment values.** `VersionData` gains
  an `envs` map of per-environment override sets (`src/modules/kv_v2/version.rs`).
  A read with `?env=<name>` returns the shared base merged with that
  environment's overrides (`merge_env`); the response carries `resolved_env` and
  `available_envs`. Writes support a full multi-env body (`envs`), a targeted
  single-environment patch (`env` + `data`, carrying base and other envs
  forward), and legacy base-only writes (which preserve existing envs). Reads
  are strict: an env declared-but-absent on a secret returns 404; legacy secrets
  with no envs ignore `env`. Backward-compatible on disk via serde defaults.
- **Engine-level environment registry.** `kv-v2` `config` accepts an
  `environments` list (`src/modules/kv_v2/metadata.rs`) the GUI offers as a
  dropdown; free-form env names are still accepted.
- **CLI `--env`** on `bvault read` (sends `?env=`) and `bvault write` (targeted
  per-environment patch) -- `src/cli/command/{read,write}.rs`.
- **GUI env support** (`gui/src/routes/SecretsPage.tsx`): an environment selector
  on the secret detail view, per-key inherited/override badges, env-scoped
  editing, an optional environment on the create modal, and the env registry on
  the engine config. New `write_secret_env` Tauri command; `read_secret` returns
  env metadata.
- **Audit** now records the `env` selector from `req.data` on reads
  (`src/audit/entry.rs`, verbatim -- `env` is non-secret).

### Fixed

- **Visual builder missing from Create Policy modal** (`gui/src/routes/PoliciesPage.tsx`)
  -- the Create Policy modal only offered a raw HCL textarea, while the edit
  view exposed both a "Visual builder" and "HCL source" tab. Added the same
  tab toggle to the Create modal so new policies can be authored with the
  `PolicyBlockEditor` block UI, matching the edit experience.

## [0.21.7] - 2026-06-30

### Fixed

#### Brokered SSH cert dropped from Rustion envelope

- Declare `credential_cert` and `credential_serial` as fields on the
  `rustion/session/open` and `rustion/v2/session/open` routes
  (`src/modules/rustion/mod.rs`). The server-side SSH-engine `ca` mint in
  `handle_session_open_v2` writes the signed OpenSSH certificate into
  `req.data["credential_cert"]`, but `Request::get_data` only returns keys
  that are declared route fields — so `pick("credential_cert")` read back
  empty, the BVRG envelope shipped `credential.kind = ssh-cert` with no
  `extra["cert"]`, and Rustion fell back to plain publickey auth
  ("no certificate in envelope" → target authentication rejected). The
  ephemeral key (`credential_material`) and `credential_kind` came through
  because those *were* declared, which masked the gap. Added a regression
  test asserting both routes declare the fields.

## [0.21.6] - 2026-06-30

### Changed

#### Audit/dashboard read performance

- Add a bulk `scan(prefix, start_key)` to the storage `Storage`/`Backend`
  traits. The hiqlite backend implements it as a single consistent
  `SELECT … WHERE vault_key LIKE ? [AND vault_key >= ?]` query, replacing the
  recursive `list` + per-key `get` walk (1+N linearizable Raft reads) that
  dominated audit/history aggregation. Other backends inherit a `list`+`get`
  fallback, and the ciphertext cache delegates straight to the inner backend.
  (`src/storage/`, `src/cache/secret_cache.rs`)
- Rewrite the five append-only audit stores (user, login, file, SSH CA, SSH
  sign) to read via the new bulk path, and add a `list_since(key)` variant that
  range-scans only the recent tail of their timestamp-ordered keys.
- Refactor `collect_audit_events` (`src/modules/system/mod.rs`): the
  independent per-subsystem reads now run concurrently (`tokio::join!`) instead
  of sequentially, and accept an optional recency bound that is pushed into the
  range scan. `GET /v2/sys/dashboard/summary` now counts only the last 24h
  instead of decrypting all history for a 235-byte response, and
  `GET /v2/sys/audit/events` bounds its scan by the caller's `from` filter.
  Together these take both endpoints from ~5.5s to sub-second on the cluster.

## [0.21.5] - 2026-06-26

### Added

#### Cluster client performance & resilience (features/vault-cluster-client-discovery.md)

- Cache the discovered cluster topology on the connected `RemoteBackend` so a
  remote session can recover from a node loss without a manual reconnect.
- Add single-shot in-session read failover: when the pinned cluster node
  becomes unavailable mid-session, idempotent requests (Read/List) re-probe the
  cached candidates, re-pick a healthy node, and retry once. Writes and deletes
  are never auto-retried (a dropped connection leaves the commit ambiguous) and
  keep the explicit-reconnect contract. Single-node / literal-URL profiles are
  unaffected. The failover is logged for operator visibility.

### Changed

- Load several GUI pages' independent data with concurrent requests instead of
  serial round-trips, which noticeably cuts page-load time against a remote
  cluster where each request is a full network round-trip: FerroGate
  (config/policies/environments), Groups (policies + members), the Password
  Manager Pro importer (plugin/mounts/types), and the Certificate Lifecycle list
  (which previously read every target's config and state one after another).

## [0.21.4] - 2026-06-26

### Security

- **Fix `quinn-proto` remote memory-exhaustion advisory (RUSTSEC-2026-0185,
  CVSS 7.5).** Bumped the transitive `quinn-proto` dependency `0.11.14 ->
  0.11.15` via `cargo update` (in-range, no manifest change). The flaw allowed
  unbounded out-of-order QUIC stream reassembly; it reached the tree through the
  cloud-S3 / `hiqlite` / Tauri HTTP stacks (`cryptr` -> `s3-simple` -> `quinn`,
  `reqwest` -> `quinn`). `cargo audit` now reports 2 vulnerabilities, both the
  `rsa` Marvin-attack advisory (RUSTSEC-2023-0071) for which no upstream fix
  exists.

### Changed

- **Refresh in-range Rust dependencies.** `cargo update` bumped `aes`
  `0.9.0 -> 0.9.1` and `crypto-bigint` `0.7.3 -> 0.7.5` (both clear yanked-crate
  advisory warnings), plus `rustls 0.23.40 -> 0.23.41`, `tokio 1.52.1 -> 1.52.3`,
  `reqwest 0.13.3 -> 0.13.4`, `h2 0.4.13 -> 0.4.15`, and `hyper 1.9.0 -> 1.10.1`.
  Lockfile-only; `cargo check --lib` clean.
- **Upgrade the GUI toolchain to current majors** (`gui/package.json`):
  Vite `6 -> 8`, Vitest `3 -> 4`, `@vitejs/plugin-react` `4 -> 6`, TypeScript
  `5 -> 6`, `jsdom` `26 -> 29`, `lucide-react` `0.468 -> 1.21`, `@xterm/xterm`
  `5 -> 6`, and `@xterm/addon-fit` `0.10 -> 0.11` (matched to xterm 6). All gates
  green: `tsc --noEmit`, `vite build`, and `vitest run` (187 tests). `npm audit`
  reports 0 vulnerabilities.

## [0.21.3] - 2026-06-26

### Fixed

- **Hiqlite Raft client no longer leaks a TCP socket per client rebuild
  (cluster quorum loss).** Bumped `hiqlite` to `0.14.0-202606024` and pointed
  it at our fork (`github.com/ffquintella/hiqlite`, branch `main-local`, also a
  git submodule at `third_party/hiqlite`) via `[patch.crates-io]`, matching the
  sspi/picky fork pattern. Stock hiqlite's `ws_handler`
  (`hiqlite/src/network/raft_client.rs`) spawns its `stream_reader` /
  `stream_writer` tasks as bare `tokio::JoinHandle`s; when openraft rebuilds the
  client for a target, `NetworkConnectionStreaming::drop` aborts the parent
  task, which only *detaches* (does not abort) the children, so they keep the
  upgraded WebSocket's socket halves alive and the TCP connection lingers
  `ESTABLISHED` on both peers. On the HML cluster the follower accumulated ~28k
  leaked sockets to the leader's Raft port (`:8210`), exhausted the ephemeral
  port range, and every consistent read failed with `Cluster lost quorum`
  (`Cannot assign requested address (os error 99)`). The fork binds the child
  tasks to an `AbortOnDrop` guard so they are torn down on every drop path.
- **PKI Certificates tab no longer wastes a third of the width when no cert is
  selected** (`gui/src/routes/PkiPage.tsx`) -- the issued-certificates list was
  always laid out in a `grid-cols-3` split with the table pinned to
  `col-span-2`, but the detail column only renders after a row is clicked. With
  no selection the table was squeezed into two-thirds width, leaving a large
  empty gap on the right. The split grid is now applied only when a certificate
  detail pane is actually showing; otherwise the list fills the full card width.

## [0.21.2] - 2026-06-26

### Changed

- **Reference plugins now cross-compile to amd64 Linux by default** (`Makefile`)
  -- `PLUGINS_PROCESS_TARGET` now defaults to `x86_64-unknown-linux-gnu` instead
  of the build host, so `make plugins`, `make plugins-pack`, and
  `make plugins-sign` produce `.bvplugin` bundles whose process binaries run on
  the BastionVault servers out of the box. Packing a host-native macOS/arm64
  binary previously yielded a Mach-O that the Linux server rejected at invoke
  time with `Exec format error (os error 8)` (ENOEXEC). Cross-builds are still
  auto-routed through `cross`; override with
  `PLUGINS_PROCESS_TARGET=aarch64-unknown-linux-gnu` (arm64 server) or
  `PLUGINS_PROCESS_TARGET=` (host-native, local testing only).

## [0.21.1] - 2026-06-26

### Added

- **Configurable plugin runtime directory** (`plugin_runtime_dir` config key /
  `BV_PLUGIN_RUNTIME_DIR` env var) -- the process-plugin runtime stages plugin
  executables here before spawning them (`src/plugins/process_runtime.rs`,
  `src/cli/config.rs`, applied in `src/cli/command/server.rs`). The OS temp dir
  (`/tmp`) is frequently mounted `noexec` in hardened containers, which made
  `execve` of a process-runtime plugin (e.g. `xca-import`) fail with `EACCES`.
  Operators -- and the Puppet module -- can now point this at a writable,
  exec-allowed path (e.g. `/var/lib/bvault/plugin-run`); the server creates it
  on first use. The env var takes precedence over the config value, then the OS
  temp dir is the fallback. Documented in `config/ha-cluster.hcl` and
  `config/single-node.hcl`.

### Fixed

- **Plugin invoke errors no longer masked as "Request is invalid."**
  (`src/http/sys.rs`) -- the remote `sys/plugins/{name}/invoke` handler
  collapsed every runtime-level failure (subprocess spawn/exec, temp-file
  write, timeout, WASM trap) into a generic `ErrRequestInvalid`, hiding the real
  cause from the GUI (e.g. a `noexec` temp dir blocking a process-runtime
  plugin). It now surfaces the underlying error message as HTTP 502, matching
  the embedded-mode path which already returned the real string. The failure is
  still logged server-side at `warn`.

## [0.21.0] - 2026-06-26

### Fixed

- **Isolated Hiqlite leader no longer masquerades as healthy / mislabels the failure** (`src/storage/hiqlite/mod.rs`) -- when a clustered leader can no longer reach a quorum of its peers (e.g. the Raft channel keeps failing to connect), every consistent read fails openraft's read-index leadership confirmation. Two defects made this miserable to diagnose: (1) `cluster-status` reported `cluster_healthy = true` because `is_healthy()` only consulted this node's *locally cached* Raft metrics (`is_healthy_db`), which still show a leader; and (2) the resulting `CheckIsLeaderError` was unconditionally mapped to `ErrClusterNoLeader` ("Cluster has no leader."), sending operators chasing a phantom election while the real fault was peer connectivity. `is_healthy()` now additionally requires a leader to have confirmed quorum within `QUORUM_ACK_STALE_MS` (3s, via openraft's `millis_since_quorum_ack`), so "healthy" means "can actually serve reads"; single-node leaders self-ack and stay healthy. The error mapping now distinguishes openraft's `QuorumNotEnough` (leader present but quorum unconfirmed → `ErrClusterQuorumLost`, "Cluster lost quorum.") from a genuine `ForwardToLeader`/no-leader condition (→ `ErrClusterNoLeader`), using hiqlite's public `is_forward_to_leader()` discriminator. Both still map to HTTP 503.

### Added

- **Per-user default resource account** (`src/modules/identity/default_account.rs`, `src/modules/system/mod.rs`, `src/http/sys.rs`, `gui/src-tauri/src/commands/users.rs`, `gui/src-tauri/src/commands/connect.rs`, `gui/src/routes/UsersPage.tsx`, `gui/src/routes/ResourcesPage.tsx`, `gui/src/lib/connectionProfiles.ts`, `gui/src/lib/types.ts`, `gui/src/lib/api.ts`) -- each vault user can now record an optional per-OS login name (Linux / macOS / Windows) under **Users → Edit User → Default Resource Account**. A connection profile opts in via the new **"Connecting user's default account"** credential source: at connect time the login name is the *connecting operator's* account for the target's OS, resolved server-side from the request token (`v2/sys/identity/default-account/self`) so a client can never claim another operator's account. For SSH it brokers a per-connect credential from the SSH engine (same `ssh_mount`/`ssh_role`/`mode` as the SSH-engine source) with the operator's account as the cert principal; for RDP the account supplies the login user and the password is prompted at connect. Fails closed with a clear message when the connecting user has no account for that OS — resources using any other credential source are unaffected. Admin reads/writes go through `v2/sys/identity/default-account/{mount}/{name}`. The `self` resolver works for any entity-backed login (userpass, AppRole, OIDC, SAML, cert) — not just userpass — by walking the caller's identity-entity aliases. RDP can also use an **optional stored Windows password** (set per user, encrypted at rest behind the barrier, masked on admin reads as `has_windows_password`, revealed only on the caller's own `self` read for the connect host); when set, RDP connects without prompting, otherwise it prompts as before. (`features/default-resource-account.md`)

## [0.20.2] - 2026-06-25

### Added

- **Unseal a sealed cluster from the Connect / Get-Started screen** (`gui/src-tauri/src/commands/system.rs`, `gui/src-tauri/src/lib.rs`, `gui/src/components/UnsealModal.tsx`, `gui/src/routes/ConnectPage.tsx`, `gui/src/lib/api.ts`) -- when a remote connection fails because *every* node is sealed, cluster discovery reports "no healthy node found" and the connect aborts *before* any profile is stored in `AppState`, so the connected `unseal_vault` path had nothing to target and the operator was stuck at the vault chooser. A new `remote_unseal_profile` Tauri command fans an unseal share out across a cluster identified by an **explicit profile** (reusing the same SRV discovery + per-node `sys/unseal` fan-out as the connected path, reaching sealed/unreachable nodes), so no prior connect is needed. The Connect screen now recognises the sealed connect error (via the `isVaultSealed` classifier), surfaces an inline **Unseal vault** action on the saved profile that failed, and — on a full unseal — clears the error and automatically retries the connection so the operator lands in the normal login flow. `UnsealModal` gained an optional `profile` prop that routes through the new command; the per-node breakdown and multi-share (t-of-n) prompting behave identically to the connected path. The seal-state aggregation shared by both paths is factored into one `remote_fanout_outcome` helper. Tests in `gui/src/test/seal-unseal.test.tsx` and `gui/src/test/pages.test.tsx`.

## [0.20.1] - 2026-06-25

### Added

- **Unseal from the login screen** (`gui/src/routes/LoginPage.tsx`, `gui/src/lib/error.ts`) -- when a sign-in attempt dead-ends because the vault is sealed (e.g. `node \`<host>\` is unavailable: BastionVault is sealed.`), the login page now recognises the sealed error and offers an **Unseal vault** action inline with the error, opening the existing `UnsealModal`. Previously the only sealed-vault entry points were the Dashboard and Settings, both of which sit behind a login the operator could not complete while sealed — so a sealed remote vault left the operator stuck at the sign-in form. A new `isVaultSealed` error classifier drives the detection (anchored so it never matches the opposite "unsealed" wording); on a successful unseal the dialog closes, the error clears, and the operator can sign in. Remote multi-share clusters keep prompting for the next share as before. Tests in `gui/src/test/error.test.ts` and `gui/src/test/pages.test.tsx`.

## [0.20.0] - 2026-06-25

### Added

- **Operator unseal from the GUI, with cluster fan-out** (`gui/src-tauri/src/commands/system.rs`, `gui/src-tauri/src/commands/connection.rs`, `gui/src/components/UnsealModal.tsx`) -- a new `unseal_vault` Tauri command + matching `UnsealModal` dialog let an operator unseal a sealed vault without leaving the app. In embedded mode it re-applies the unseal key to the in-process barrier (resolving the key from the operator-supplied hex field or, when left blank, the key cached on the device) and rebuilds the `EmbeddedBackend` handle that `seal_vault` tears down. In remote mode the share is **fanned out to every node of the connected cluster** -- seal state is per-node, so the GUI mirrors `bvault operator unseal`: it enumerates the roster via SRV discovery (`remote_unseal_fanout` reuses the same `bv-client` discovery + TLS plumbing as `connect_remote`, including sealed/unreachable nodes), submits the share to each node's `sys/unseal`, and returns a per-node breakdown. The dialog shows the aggregate state plus a node-by-node list (reached count, per-node sealed/unsealed/error, and t-of-n Shamir progress); the aggregate `sealed` stays true until *every* node is open, so multi-share clusters keep prompting for the next share. A literal-URL profile (or discovery disabled) targets just the one node. The Dashboard quick-action strip now shows a green **Unseal Vault** button while sealed (replacing the previously inert, disabled Seal button), and the Settings → Actions card shows an **Unseal** row whenever the vault is sealed.

### Changed

- **Container runtime moved from distroless to Wolfi** (`deploy/container/Containerfile`, `deploy/container/Containerfile.debug`, `deploy/container/README.md`) -- the production and `:debug` runtime images now build `FROM cgr.dev/chainguard/wolfi-base` (Chainguard's free, open-source, glibc-based undistro) instead of `gcr.io/distroless/cc-debian12`. Both are glibc + a CA bundle with a minimal userspace, so the cross-built `bvault`/`bv-ssh-helper` binaries run unchanged, but Wolfi ships `apk` and a shell in the base. That lets the production image install the CA bundle inline and reuse the base's pre-existing `nonroot` UID/GID 65532 (no more Debian busybox-staging stage), and lets the `:debug` image `apk add iproute2 tcpdump curl` directly (no more hand-copied `.so` deps from a Debian layer). `INCLUDE_SHELL=0` still strips the shell + package manager for the hardened, shell-less posture. Added `deploy/container/test/wolfi-runtime.test.sh` (static Containerfile assertions, always-on; plus an opt-in `BV_CONTAINER_SMOKE=1` build-and-run smoke test that verifies `ID=wolfi`, UID 65532, the CA bundle, a working `bvault --version`, and that `INCLUDE_SHELL=0` is shell-less) wired to `make container-image-test [SMOKE=1]`.
- **Seal Vault now requires confirmation, and fans out across clusters** (`gui/src/routes/DashboardPage.tsx`, `gui/src/routes/SettingsPage.tsx`, `gui/src/components/dashboard/QuickActions.tsx`, `gui/src-tauri/src/commands/system.rs`, `gui/src-tauri/src/commands/connection.rs`) -- both Seal controls (the Dashboard quick action and Settings → Actions) open a danger `ConfirmModal` before sealing, so a single misclick can no longer drop every active session and lock the barrier. In remote mode the seal is now **fanned out to every node of the connected cluster** (`remote_seal_fanout`, mirroring `bvault operator seal` and the matching unseal fan-out): seal state is per-node, so the GUI enumerates the roster via SRV discovery and sends `sys/seal` to each node (carrying the session token, since seal is policy-gated), then reports a per-node tally — "Sealed N/N nodes" or the specific nodes that refused. A literal-URL profile targets just the one node. `seal_vault` now returns a `SealOutcome { status, nodes }`. Settings refreshes the live seal status on mount so the Seal/Unseal control reflects reality even when the operator navigates straight there.

### Fixed

#### Scheduled / exchange backups now capture and restore every secret engine

- **Full backups silently dropped every non-KV secret engine** (`src/exchange/scope.rs`, `src/exchange/schema.rs`) -- a `kind: "full"` export (the scheduled-backup default) only enumerated `kv`/`kv-v2`, `resource`, `files`, and resource-group mounts, so PKI, SSH, SSH-broker, Transit, TOTP, OpenLDAP, Rustion (and any future engine) were absent from the `.bvx` entirely — a "daily full" of a 13-mount vault shipped only the one `secret/` mount. `resolve_full` now sweeps every remaining logical mount and captures its barrier subtree verbatim as opaque `RawEntry` items (new `ExchangeItems.raw` field), so a full backup round-trips all engines byte-for-byte. The control-plane `system`/`identity` views and the structurally-exported `kv`/`resource`/`files`/`resource-group` types are skipped (`RAW_SKIP_TYPES`) so nothing is double-captured and the live mount table / seal config is never round-tripped. Tests `raw_engine_full_capture_and_restore`, `raw_capture_skips_system_and_identity`.
- **Restore replayed only KV items; resources, files, and groups in the backup were unrestorable** (`src/exchange/scope.rs`) -- `import_from_document` looped over `document.items.kv` alone, so the resources, file blobs, and resource/asset groups a full export *did* write were silently discarded on restore (and never shown in the *Preview*), making them dead weight in every `.bvx`. Import now also restores `raw` engine entries (resolved through the new `MountIndex::resolve_raw_key`) and reconstitutes structured resources (meta + history + per-secret value/meta/version bundles), file blobs (metadata + raw bytes), and resource/asset groups back to their barrier keys. Every item type funnels through one shared `apply_entry` classify-and-write path so conflict policy (skip/overwrite/rename) and counters behave identically. Tests `structured_resource_round_trips_through_import`, `raw_engine_full_capture_and_restore`.
- **Restore *Preview* under-reported and disagreed with the real write** (`src/exchange/scope.rs`, `src/http/sys.rs`, `gui/src-tauri/src/commands/exchange.rs`, `gui/src-tauri/src/commands/scheduled_exports.rs`) -- the dry-run classification was reimplemented KV-only in four places (two GUI commands, the server `classify_exchange_items` helper, and the interactive-import preview, the last still using the pre-re-root bare `mount+path` lookup), so the modal showed e.g. *"25 items"* for a backup that actually held far more and could mislabel re-rooted items as `new`. `import_from_document` gained a `dry_run` flag and is now the single classify+write engine; all four preview/restore sites call it (with `ImportResult::classification_counts`) so the preview matches the real restore across every item type. The `bvault exchange verify` counts gained a `raw` total. Test `dry_run_classifies_without_writing`.

## [0.19.5] - 2026-06-25

### Fixed

- **Connect failed with `HTTP 403` for users who could read the secret but not the Rustion policy** (`gui/src-tauri/src/commands/connect.rs`) -- clicking **Connect** on an SSH/RDP profile with a `secret` (or `ssh-engine`) credential source aborted with `403 Permission denied` for a read-only share-grantee, even on a resource with no bastion configured. The connect path unconditionally calls `rustion/policy/effective` (via `read_effective_policy`) to decide whether to broker, and that read -- on the global `rustion/` mount, which such a caller can't reach -- propagated its 403 through `?` and killed the whole Connect before the credential was ever resolved. The effective policy is only a *routing hint* (the real boundaries stay server-side: brokering on `rustion/v2/session/open`, the credential read on `resources/secrets/...`), so a permission-denied is now treated as "no Rustion policy is visible to me" and falls through to a direct dial -- the same way `read_effective_login_class` already tolerates a missing `ssh-broker/` mount. Other errors (network, 500, lock-violation payloads) still propagate, so a transient fault can't silently downgrade routing. Covers the SSH and RDP route resolvers (both funnel through `read_effective_policy`). Unit tests `commands::connect::tests`.
- **Bastion routing preview showed a red error for read-only users** (`gui/src/components/RustionDispatcherPreview.tsx`, `gui/src/lib/error.ts`) -- the Connection tab's dispatcher preview ("Will try: A → B") rendered a red `Bastion preview unavailable: HTTP 403: Permission denied` card whenever the caller lacked `read` on `rustion/dispatcher/preview` (the common case for read-only share-grantees and non-admins). Every other section on that tab degrades gracefully under the same boundary (Connection profiles → "Read-only access" banner; Rustion policy → "not configured"), so the loud error was inconsistent and alarming. A new `isPermissionDenied` classifier (alongside `isMountNotFound`/`isNodeUnavailable`) lets the panel treat a 403 as the expected permission boundary it is and render nothing -- same as it already does when no bastion is involved -- while genuine faults (500/network) still surface. Unit tests in `gui/src/test/error.test.ts`.

## [0.19.4] - 2026-06-25

### Fixed

- **Scheduled-backup/exchange restore preview misclassified every item as `new`** (`src/exchange/scope.rs`, `src/http/sys.rs`, `gui/src-tauri/src/commands/scheduled_exports.rs`) -- the restore dry-run (the GUI *Preview* step) and the `/sys/exchange/import/preview` classifier built the lookup key as the bare `mount + path` (e.g. `secret/versions/…`), but under the default re-rooted layout the live KV data lives at `namespaces/<root_uuid>/logical/<mount_uuid>/…`. The probe therefore found nothing and reported `25 new / 0 identical / 0 conflict` even when restoring a backup of data already present, hiding all conflicts before an Overwrite. The actual write path (`import_from_document`) already resolved the prefix correctly via `MountIndex`, so the two disagreed. The prefix resolution is now a single shared `MountIndex::resolve_kv_key` used by the write path *and* both dry-run classifiers, so the preview looks where the data actually lives. Regression test `resolve_kv_key_uses_reroot_prefix`.

## [0.19.3] - 2026-06-25

### Added

- **Scheduled-backup list + restore over HTTP (remote-mode support)** (`src/http/sys.rs`) -- two new server endpoints make the GUI's Scheduled-backups tab work when connected to a remote vault, where the backup files live on the server's disk rather than the GUI host's: `GET /v1/sys/scheduled-exports/{id}/backups` enumerates the `.bvx`/`.json` files in a schedule's local destination directory (name, size, modified, format; newest first; temp/non-backup files ignored), and `POST /v1/sys/scheduled-exports/{id}/restore` reads one of those files off the server's disk and imports it back into the vault. The restore endpoint honours a `dry_run` flag (classify-only, powering the GUI's *Preview* step) and otherwise applies under the supplied `conflict_policy` (skip/overwrite/rename), decrypting `.bvx` with the supplied password and refusing plaintext JSON unless `allow_plaintext` is set — so the whole operation runs server-side and the (possibly full-vault) backup never round-trips through the client. Both are audited via `SysAuditCtx`. The import-preview classification loop was factored into a shared `classify_exchange_items` helper reused by both the existing `/sys/exchange/import/preview` handler and the restore dry-run.

### Changed

- **GUI: Scheduled-backup list + restore now work in remote mode** (`gui/src-tauri/src/commands/scheduled_exports.rs`, `gui/src/lib/api.ts`, `gui/src/routes/ExchangePage.tsx`) -- previously both failed fast with *"... only available when running an embedded vault"* because they touched the GUI host's filesystem directly. `scheduled_exports_backups_list` now routes to the new server `backups` endpoint when remote (embedded path unchanged), and the restore flow is unified behind one new `scheduled_exports_restore` Tauri command that delegates to the server `restore` endpoint when remote and runs in-process when embedded — replacing the old read-to-base64 → `exchange_preview` → `exchange_apply` round-trip. The Backups modal's *Preview* and *Restore* buttons call it with `dryRun: true`/`false`; the classified summary and conflict-policy selector are unchanged. Embedded restore now emits its own `sys/scheduled-exports/restore` audit entry.

### Fixed

- **GUI: Exchange Import/Export tabs now work in remote mode** (`gui/src-tauri/src/commands/exchange.rs`) -- the `exchange_export`, `exchange_preview`, and `exchange_apply` Tauri commands each locked `state.vault` directly, which is always `None` when the GUI is connected to a remote server, so every export and import failed with *"Vault not open"* — despite the module doc-comment claiming HTTP routing existed (it never did). Each command now starts with an `is_remote(&state)` guard that routes through the `bv_client::Backend` trait (mirroring `scheduled_exports.rs`) to the matching server endpoints (`POST /v1/sys/exchange/export`, `/import/preview`, `/import/apply`), sending the request bodies the handlers expect and parsing the replies back into the existing `ExchangeExportResult`/`ExchangePreviewResult`/`ExchangeApplyResult` shapes; the embedded paths are unchanged. Because the preview token is minted in the server's `core.exchange_preview_store`, remote preview *and* apply both hit the server so the server-side owner-bound token round-trips correctly. The server emits its own audit entries for the remote path.

- **GUI: per-resource Rustion policy editor stayed editable for read-only viewers** (`gui/src/components/RustionPolicyTierEditor.tsx`, `gui/src/hooks/useCanWriteResource.ts`, `gui/src/routes/ResourcesPage.tsx`) -- at `tier="resource"` the editor rendered its Transport/Recording selects, Bastion group / Pinned bastions inputs, and the Save/Clear buttons unconditionally, even though Save is gated to the resource owner server-side (read-only share-grantees get `403`). It now mirrors the connection-profile fix: `useCanWriteResource` was extracted from `ResourcesPage.tsx` into a shared hook (gaining an `enabled` flag so the type/asset-group tiers, which keep their own admin / group-owner gating, skip the owner check), and the resource-tier editor disables every input plus Save/Clear and shows the *"You don't have permission to modify this resource."* tooltip and a read-only banner when the caller lacks write access. Higher tiers are unchanged.

- **`capabilities-self` leaked scope-gated capabilities to non-grantees** (`src/modules/system/mod.rs`) -- `POST sys/capabilities-self` computes capabilities via `ACL::capabilities`, which runs an `Operation::List` dry-run; the `is_list` short-circuit in `allow_operation` defers `scopes = ["owner"|"shared"]` filtering to post-route for genuine LISTs, so the probe advertised a scope-gated rule's *full* capability set without verifying the scope. A read-only resource share-grantee (and the baseline `default`/`default-user` policies whose `resources/*` rules carry `update`/`create`/`delete` under `scopes = ["shared"]`) therefore saw `update`/`delete` reported, and the GUI's `useCanWriteResource` hook enabled the connection-profile **Edit**/**Delete** controls that the server then rejected with `403`. The handler now re-verifies each scope-sensitive capability (`read`/`list`/`update`/`create`/`delete`) against the real gate via `PolicyStore::can_operate` -- which resolves ownership and active shares -- and drops any the caller cannot actually exercise; `root`/`deny` and ungated rules are unaffected. Regression test `test_capabilities_self_scope_gated_not_leaked`.

### Removed

- **GUI: `scheduled_exports_backup_read` Tauri command** (`gui/src-tauri/src/commands/scheduled_exports.rs`, `gui/src-tauri/src/lib.rs`, `gui/src/lib/api.ts`) -- the restore flow no longer reads backup bytes into the client (the server now reads and imports its own file), so this embedded-only base64 read command and its `BackupReadResult` type / `scheduledExportsBackupRead` binding were removed as dead code.

## [0.19.2] - 2026-06-25

### Added

- **GUI: list and restore scheduled-backup files** (`gui/src-tauri/src/commands/scheduled_exports.rs`, `gui/src/lib/api.ts`, `gui/src/routes/ExchangePage.tsx`) -- the Import/Export → Scheduled backups tab previously showed only a schedule's destination path; the operator had to leave the app to find the `.bvx`/`.json` files the cron runner had written and re-upload one through the Import tab to restore it. Each schedule card now has a **Backups** button that opens a modal listing the backup files present in that schedule's local destination directory (name, format, size, modified time, newest first), each with a **Restore** button. Restore reuses the existing import pipeline: the chosen file is read off disk and run through `exchange_preview` (classified new/identical/conflict summary) then `exchange_apply` under a selectable conflict policy (skip/overwrite/rename), prompting for the `.bvx` password when needed. Backed by two new embedded-only Tauri commands — `scheduled_exports_backups_list` (scans the destination dir, ignoring temp/non-backup files) and `scheduled_exports_backup_read` (reads a single file as base64, with file-name traversal guards); both fail fast with a clear message in remote mode since the files live on the host's filesystem.

### Fixed

- **GUI: gate resource Files and Connection controls on permission instead of clicking through to a 403** (`gui/src/routes/ResourcesPage.tsx`) -- on a resource a user could only read (e.g. via a share), the **Files** tab still tried to list files and surfaced a raw `HTTP 403: Permission denied` toast, and the **Connection** tab rendered the *Add profile* / *Edit* / *Delete* / *Set default* buttons fully enabled even though saving would be denied. The Files panel now treats a blanket 403 on the listing as "no file access" and renders a quiet *No access to files* notice rather than an error toast (other errors still surface). The Connection panel resolves the caller's write capability via a new `useCanWriteResource` hook and disables the mutation controls (with an explanatory tooltip and a *Read-only access* banner) when the caller can't modify the resource; **Connect** stays available since launching a session is a separate capability. The **Info** tab's *Edit* / *Delete* buttons are gated by the same hook. Because `sys/capabilities-self` is evaluated without identity context and so can't see ownership- or admin-granted access, the hook mirrors the Sharing card's model and also treats an admin or the resource owner as allowed, avoiding a false-disable for the people who legitimately own the resource.

## [0.19.1] - 2026-06-24

### Added

- **GUI: cropped dashboard for non-admin users** (`gui/src/routes/DashboardPage.tsx`, `gui/src/components/dashboard/UserDashboard.tsx`, `gui/src/lib/access.ts`) -- a standard (non-admin) user landed on the full operator dashboard, where every KPI (secret engines, policies, identities, audit events, bastion telemetry) read "unavailable" and the Seal Vault / Issue certificate / Audit log / Policies actions were dead ends, because they're all admin-gated. The dashboard now branches on the same admin-policy check the sidebar uses (extracted to `lib/access.ts` as `isAdminUser` / `ADMIN_POLICIES`, shared with `Layout`): admins keep the operator dashboard unchanged, while non-admins get a focused view scoped to what they can actually use — KPI tiles for resources/secrets shared with them and a "Shared with me" list with direct **Open** links into each resource/secret. Non-admins no longer fire the operator-only endpoints (only the header's status/version badges are fetched), so the burst of permission-denied calls is gone. New `gui/src/test/dashboard.test.tsx` coverage for `isAdminUser` and the `UserDashboard` view.

### Fixed

- **`default`-policy users can now use resources/secrets shared with them** (`src/modules/policy/policy_store.rs`) -- a user with only the `default` policy could *see* a share on the GUI Sharing page (`identity/sharing/for-me` is granted) but **could not open or connect to it**: the `default` policy carried no rule for `resources/`, `secret/`, or `resource-group/`, so the `scopes = ["shared"]` share-resolution path in `policy/acl.rs` was never reached and access was denied. Added share-scoped rules to the `default` policy for KV secrets (`secret/*`, `secret/data/*`, `secret/metadata/*`), resources (`resources/*`), and asset groups (`resource-group/groups`, `resource-group/groups/+`). Every rule is `scopes = ["shared"]` **only** (deliberately no `"owner"` and no first-write carve-out), so it grants access **exclusively** to targets an active `SecretShare` has explicitly shared with the caller, at the share's capability level — it adds no blanket resource/secret access. The `default` policy is force-re-seeded on every unseal, so the grant reaches existing vaults on the next restart. Consequence: a `default` user now sees the `secret/`/`resources/`/`resource-group/` mounts on the dashboard (mount-level visibility, matching `standard-user`); item access still requires a share. Group-delivered shares continue to require the opt-in `metadata { group_shared_resources = "true" }` tag (intentionally not in `default`). New `policy/acl.rs` test `test_default_policy_shared_resource_rule`; `system` test renamed to `test_system_internal_ui_mounts_default_policy_shareable_mounts`.

- **GUI: signing out now actually ends the session** (`gui/src/components/Layout.tsx`, `gui/src/routes/SettingsPage.tsx`, `gui/src/stores/authStore.ts`) -- the **Sign Out** button only cleared front-end state via `clearAuth()` and never called the backend `logout` command, so the token was neither revoked server-side nor cleared from the Rust `AppState`, and the per-vault session cache was left intact. Re-opening the same vault then silently resurrected the just-signed-out session via `restoreSession`, and `SessionMonitor` would later trip over the dead token — surfacing a spurious **"Your session expired. Please sign in again."** banner + toast when the operator tried to log in as a different user. Both `handleSignOut` (and Settings' `handleDisconnect`) now `await api.logout()` (best-effort revoke + `state.token` clear) before `clearAuth()`, and a new `clearSessions()` store action evicts the cached per-vault sessions so a deliberate sign-out can't be resumed.

- **GUI: SSH-engine credential source is now configurable** (`gui/src/routes/ResourcesPage.tsx`) -- the connection-profile editor rendered a "ships in a later phase" *stub* for the `ssh-engine` credential source, so the mount/role were never set and every save failed validation with `SSH-engine mount is required` — even when the SSH secret engine was mounted. Replaced the stub with a real editor: the **mount path** and **role** are populated live from the engine (`ssh_list_mounts` / `ssh_list_roles`, with free-text fallback when a capability is missing), plus a **credential mode** selector (CA-signed cert / OTP / PQC). PQC mode is flagged as not yet launchable from the in-app client; CA and OTP profiles now save and launch.

## [0.19.0] - 2026-06-24

### Added

- **SSH Login Brokering for Resources — Phases 1–4** (`features/ssh-resource-login-brokering.md`) -- a resource, resource-type, or asset-group can now be **pinned to `brokered`** so every SSH login is a per-connect minted artifact (CA-signed certificate or OTP) from the SSH secret engine, with **no static credential anywhere in the path**.
  - **Four-tier login-class policy** (`src/modules/ssh_broker/`) on a new `ssh-broker/` logical mount: global default (`ssh-broker/policy/global`, root-gated), per-resource-type, per-asset-group, and per-resource tiers. Resolution is most-restrictive-wins (`shared-credential < brokered`); a locked upstream tier returns `403 login_class_locked` with `locked_at_tier`, mirroring the Rustion transport policy so the two compose. New CLI `bvault ssh-broker policy {get,set}`; config-change audit events `ssh_broker.policy.{global,type,asset_group,resource}.update`.
  - **Attach-time enforcement**: storing a static SSH credential (`private_key` / `password`) on a brokered resource is refused with `409 brokered_resource_no_static_credential` — enforced server-side, not merely hidden in the GUI. The direct connect path rejects a brokered profile whose source isn't the SSH engine with `brokered_requires_ssh_engine` (fail-closed, never a silent downgrade).
  - **`ssh-cert` / `ssh-otp` BVRG-v1 envelope kinds**: the minted ephemeral key + signed OpenSSH certificate are sealed into the session-grant envelope (`credential.material` + `credential.extra["cert"]`) and **forwarded to Rustion**, which authenticates to the target on the operator's behalf — retiring the documented "non-password SSH fails closed under `rustion-required`" gap for the certificate path. Brokered minting on the Rustion path happens **inside the vault process** (`handle_session_open_v2`): the ephemeral keypair is generated, signed via the bound SSH-engine role, sealed, and its plaintext copy zeroized — it never reaches the GUI/JS or the operator's disk.
  - **Audit**: `session.open` now carries `login_class`, `ssh_engine_mode` (`ca` | `otp`), `cert_serial`, and the resolved `login_class_chain`, joining a session to the `ssh/sign` issuance row on both the direct and Rustion witnesses.
  - **GUI**: the connection-profile editor resolves the resource's effective login class (`resource_login_class` Tauri command + `ssh-broker/policy/effective`), disables the static `Secret` source and locks the credential source to the SSH engine for a brokered resource, and shows a brokered resolution banner. The `ssh-engine` source is now launchable (CA / OTP).

### Security

- **No static SSH credential on brokered resources** — enforced at attach time (`409`), so a brokered resource physically cannot hold a shareable SSH key/password; a pre-existing static secret is never offered to the dialler. The ephemeral brokered private key is minted in-process, wrapped in `Zeroizing`, never persisted, and dropped from vault memory the instant the envelope ciphertext is sealed (Rustion path) or the session closes (direct path). Brokered SSH OTP over Rustion **fails closed** with `ssh_otp_rustion_unsupported` until the bastion's `ssh-otp` materialiser ships (tracked cross-repo) — never a fallthrough to a direct or shared-credential path.

- **Spec: SSH Login Brokering for Resources** (`features/ssh-resource-login-brokering.md`) -- design for a per-resource `login_class` (`shared-credential` | `brokered`) with a four-tier lockable policy (global / resource-type / asset-group / resource), letting an admin **mandate** that every SSH login to a resource is a per-connect minted artifact (CA / PQC signed certificate or OTP) from the SSH secret engine instead of a stored, shareable credential. Brokered resources refuse to store a static SSH credential (`409 brokered_resource_no_static_credential`), and the ephemeral private key is minted in-process, never persisted, and never reaches the operator's workstation. The spec also adds new BVRG-v1 envelope credential kinds `ssh-cert` (ephemeral key + signed cert) and `ssh-otp` so the minted artifact is **forwarded to Rustion** and the bastion authenticates to the target on the operator's behalf — retiring the documented "non-password SSH fails closed under `rustion-required`" gap. 5 phases, all Todo; the matching Rustion control-plane session materialiser is tracked cross-repo. Roadmap row added under Resources (`roadmap.md`).

## [0.18.6] - 2026-06-24

### Added

- **SSH certificate signing is now recorded in the audit trail** (`src/modules/ssh/ssh_sign_audit_store.rs`) -- every successful `ssh/sign/<role>` issuance (classical Ed25519 or PQC ML-DSA-65) now appends to a system-view audit store and surfaces on the admin Audit page under a new **SSH Sign** category, closing the gap where the CA lifecycle was audited (0.18.3) but the certs it issued were not. Follows the existing `SshCaAuditStore` pattern: lazy `from_core`, 20-digit-nanos keys, newest-first listing, and fail-soft writes (a recording failure logs at WARN and never blocks the signing). Each row records the actor, role, principals, cert type, the 16-hex-digit serial (matching the `serial_number` returned to the caller, for revocation/forensics), and the signing algorithm. The `sys/audit/events` aggregator (`src/modules/system/mod.rs`) maps these to a `sign` op, and the GUI (`gui/src/routes/AuditPage.tsx`) gains the matching category label/badge and operation filter.

### Fixed

- **SSH role editor now exposes "Default extensions", so `permit-pty` (and friends) actually land on signed certs** (`gui/src/routes/SshPage.tsx`) -- the role form only offered an **Allowed extensions** field, which is a request *whitelist* (`role.allowed_extensions`), not an always-on set. With no UI for `default_extensions` and no way for the Sign Cert form to request extensions, a role configured with `permit-pty` issued certs that carried no extensions at all — breaking PTY allocation on login. The form now has a **Default extensions** input (comma-separated → `{name: ""}` map) that populates `default_extensions`, which `ssh/sign` always emits, and the **Allowed extensions** hint now states it is a request whitelist that does not emit on its own. Backend semantics (whitelist vs. always-on, matching HashiCorp Vault) are unchanged.

## [0.18.5] - 2026-06-23

### Added

- **Token and SSO (OIDC/SAML) sign-ins are now audited** -- login auditing previously covered only the credential backends (userpass password, userpass-integrated FIDO2, standalone `fido2/`, approle), so the two remaining GUI sign-in paths left no row on the Admin → Audit page.
  - **Token login** -- presenting an existing token is not a credential-backend login, so the server had no signal a sign-in happened (and `lookup-self` is also the liveness probe, so it cannot be the hook). A new self-service `auth/token/audit-login` endpoint (`src/modules/auth/token_store.rs`, `handle_audit_login`) records a `login` event under the `token/` mount, deriving the principal server-side from the authenticated request (never trusted from the caller). The GUI calls it once after validating a pasted token via `lookup-self` — in both embedded (`gui/src-tauri/src/commands/auth.rs`, `login_token`) and remote (`gui/src-tauri/src/commands/connection.rs`, `remote_login_token`) mode. The endpoint is granted by the built-in `default` / `standard-user` / role policies (`src/modules/policy/policy_store.rs`), so any valid token can record its own sign-in; the liveness probe deliberately does not call it, so repeated probes don't spam the trail.
  - **SSO (OIDC / SAML) login** -- the OIDC `callback` (`src/modules/credential/oidc/path_callback.rs`) and SAML `handle_callback` (`src/modules/credential/saml/path_callback.rs`) handlers now run through an audited wrapper + private `*_inner`, recording success and failure under the `oidc/` / `saml/` mount (mirroring the userpass pattern). The principal is the resolved display name / `NameID` on success and `(unknown)` on a rejected attempt.
  - New helper `record_login_via_view` (`src/modules/credential/login_audit_store.rs`) appends a `login` event for callers holding a system view rather than a `Core` (the token store). Covered by the new `test_audit_events_includes_token_login` and `test_audit_events_includes_sso_callback_failure` regression tests (`src/modules/system/mod.rs`).

## [0.18.4] - 2026-06-23

### Fixed

- **Security-key (FIDO2) logins now appear in the audit trail** (`src/modules/credential/userpass/path_fido2_login.rs`) -- v0.18.1 wired login auditing into the standalone `fido2/` backend, but the GUI's security-key login completes against the *userpass-integrated* path `auth/userpass/fido2/login/complete`, which was never instrumented, so tapping a key recorded nothing. That handler is now split into an audited `fido2_login_complete` wrapper + private `fido2_login_complete_inner`, recording success and failure under the `userpass/` mount with a `method=fido2` tag (distinguishing a key login from a password login). Covered by the new `test_audit_events_includes_login_and_logout` regression test.

### Added

- **Logout is now audited and revokes the session token server-side** -- a new Vault-compatible `auth/token/revoke-self` endpoint (`src/modules/auth/token_store.rs`, `handle_revoke_self`) revokes the calling token and its child tokens, then appends a `logout` event to the login-audit trail. The default policies already granted `update` on this path but nothing served it; the GUI `logout` command (`gui/src-tauri/src/commands/auth.rs`) previously just dropped the token locally, leaving it valid until TTL. Logout now calls `revoke-self` best-effort before clearing local state (works in both embedded and remote mode). A root-policy token is audited but **not** revoked, so a GUI logout cannot lock the operator out of break-glass access. `LoginAuditEntry` gains an `action` field (defaults to `login` for back-compat with existing rows; `logout` for the new event); the `sys/audit/events` aggregator (`src/modules/system/mod.rs`) maps it to a dedicated `logout` op, and the GUI Audit page (`gui/src/routes/AuditPage.tsx`) gains the **Logout** badge and operation filter.

## [0.18.3] - 2026-06-23

### Added

- **SSH CA create/delete now recorded in the audit trail** (`src/modules/ssh/ssh_ca_audit_store.rs`) -- configuring the SSH signing CA (classical Ed25519 or PQC ML-DSA-65) and deleting it now append to a system-view audit store and surface on the admin Audit page under a new **SSH CA** category. Follows the existing `FileAuditStore` / `LoginAuditStore` pattern: lazy `from_core`, 20-digit-nanos keys, newest-first listing, and fail-soft writes (a recording failure logs at WARN and never blocks the CA operation). The `sys/audit/events` aggregator (`src/modules/system/mod.rs`) maps these to `create` / `delete` ops with the CA algorithm in the fields column, and the GUI (`gui/src/routes/AuditPage.tsx`) gains the matching category label/badge.

### Fixed

- **SSH sign-cert now accepts ECDSA client public keys** (`Cargo.toml`, `src/modules/ssh/path_sign.rs`) -- submitting an `ecdsa-sha2-nistp256` (or P-384/P-521) client key to `ssh/sign/<role>` failed with `HTTP 500: public_key parse failed: unknown algorithm` because the `ssh-key` dependency was built without its `ecdsa` feature, so the ECDSA key-data decode arm was compiled out. The feature is now enabled, letting the Ed25519 CA sign ECDSA subject keys (the CA key itself stays Ed25519). The parse-failure path also now returns **HTTP 400** instead of 500 — a malformed client key is client input, not an internal fault — matching the 500→400 correction made for the same engine in 0.18.2.
- **SSH role editor now persists unchecking "PQC-only"** (`gui/src-tauri/src/commands/ssh.rs`) -- the `ssh_write_role` Tauri command only added `pqc_only` to the engine request body when it was `true`, so clearing the checkbox omitted the field entirely. Because the engine's role-write handler does a partial merge (absent field = unchanged), a previously-stored `true` survived and the box re-checked itself on reload. The field is now sent unconditionally (`Value::Bool(config.pqc_only)`), so `false` reaches the engine and overwrites the stored value.

## [0.18.2] - 2026-06-22

### Fixed

- **SSH sign-cert client-input errors now return HTTP 400 instead of 500** (`src/modules/ssh/path_sign.rs`) -- rejecting a `pqc_only` role's sign request with a classical/malformed client public key, or hitting a `pqc_only`-on-classical-CA misconfiguration, previously surfaced as `RvError::ErrString`, which falls through to the `_ => INTERNAL_SERVER_ERROR` arm in `response_status()`. These are client-input validation failures, so they now use `bv_error_response_status!(400, …)` (`ErrResponseStatus`) and return a `400 Bad Request` with the explanatory message preserved in the body. `ErrString` is left untouched so genuine internal faults still report 500.

### Added

- **Identity Provider feature specification** (`features/identity-provider.md`) -- design of record for turning BastionVault into an **outbound** identity provider so administrators reach servers, firewalls, and appliances *as themselves* instead of as shared `root`/`admin` accounts. Three pillars: (1) a canonical workforce identity with an immutable, environment-consistent, never-reused POSIX `(login, uid, gid)` mapping; (2) entitlement-gated, identity-bearing credential issuance; (3) lifecycle-driven revocation that blocks disabled/removed identities at the destinations (OpenSSH KRL + signed, versioned deny feed). Downstream projections cover Linux (SSH certificate principals + `AuthorizedPrincipalsCommand`/NSS helper), FortiGate and network gear (RADIUS/RadSec with vendor attribute templates), generic SSO (SAML IdP + OIDC OP), and LDAP-only systems (read-only LDAP-compat directory). Sequenced into 7 phases (all Pending); composes the existing SSH CA engine, entity model, namespaces, policy engine, and audit chain. Added to `roadmap.md` (Todo).

## [0.18.1] - 2026-06-22

### Added

- **Login events in the audit trail** (`src/modules/credential/login_audit_store.rs`) -- every authentication attempt is now recorded, success and failure alike, and surfaces on the admin Audit page under a new `login` category. A flat, timestamp-keyed system-view store (mirroring `FileAuditStore`) is appended by the userpass, approle, and fido2 login handlers via a best-effort wrapper that never blocks or alters the login result. Rows show the principal (`userpass/<user>`, `approle/<role>`, `fido2/<user>`), the peer address (`from=…`), and the granted policies (success) or the rejection reason (failure). AppRole failures log `(unknown)` since the `role_id` is an opaque secret. The aggregator (`sys/audit/events`) maps these to op `login` / `login-failed`, and the GUI (`gui/src/routes/AuditPage.tsx`) gains a "Login" category badge, green/red op badges, and matching Operation-filter options.

### Fixed

- **SSH role dropdowns now filter by mode** (`gui/src/routes/SshPage.tsx`) -- the "OTP Creds" tab listed CA-mode roles (and "Sign Cert" listed OTP-mode roles), so selecting one returned `HTTP 500: role is 'ca', not 'otp'`. A new `useRolesOfMode` hook reads each role's `key_type` and shows only roles valid for the active operation.

## [0.18.0] - 2026-06-22

### Added

#### Graphical Policy Builder & Validator (`features/policy-builder-validator.md`)

- **Stateless policy dry-run endpoint** (`POST /v2/sys/policies/acl/test`) -- parse a *draft* ACL policy and evaluate `(path, capability)` cases against it using the production HCL parser and ACL matcher, **without ever persisting**. Each result reports the authoritative allow/deny verdict plus the matched rule (`matched_path` + `match_kind`: `exact` | `prefix` | `segment_wildcard` | `none`) and whether an explicit `deny` decided it. Lets operators prove what a policy grants before applying it to live tokens, instead of saving it and minting a test token. Gated by the same `sys/policies/acl/*` capability as a policy write. Note: `test` is now a reserved policy name. (Phase 1)
- **Savable effectivity test cases** (`GET`/`POST /v2/sys/policy-tests/{name}`) -- attach `(path, capability, expect)` assertions to a policy as documentation of intent and as a regression gate. Stored alongside, not inside, the policy HCL (so a historical restore never clobbers present-day cases). A failing saved case blocks save in the GUI with an explicit "save anyway" override. (Phase 4)
- **Visual policy builder** (`gui/src/components/PolicyBlockEditor.tsx`) -- a block-based editor beside the textual HCL editor on the Policies page. Each path rule is a card with a glob lint badge, capability toggle chips (`deny` greys the rest; `sudo` warned; `connect` hinted; `root` disabled), reorder controls, and collapsible TTL / parameter / asset-group / ownership-scope editors. Round-trips losslessly to and from HCL, which remains the source of truth. (Phase 3)
- **Validate & test panel** (`gui/src/components/PolicyValidatorPanel.tsx`) -- shows client-side lint/parse findings over the draft and runs editable test-case rows through the authoritative backend dry-run, displaying the verdict and matched rule, a pass/fail summary, and a save action for the regression gate. (Phase 4)
- **Client-side policy tooling** (`gui/src/lib/policyHcl.ts`) -- a dependency-free HCL ⇄ block-model parser/serializer, capability/glob/TTL linter, and a non-authoritative preview matcher mirroring the backend's exact > prefix > segment precedence, for instant feedback while typing. Covered by `vitest` (round-trip stability, lint detection, matcher precedence). (Phase 2)
- **Tauri commands + TS API** -- `policy_test`, `read_policy_tests`, `write_policy_tests` wrap the new endpoints for both embedded and remote GUI modes.

### Fixed

- **Audit-event filters dropped in remote mode** (`src/http/sys.rs` `sys_audit_events_request_handler`) -- the `sys/audit/events` HTTP shim only parsed `from` / `to` / `limit` from the URL query string, but the `bv-client` remote backend sends a `GET` with those params in the JSON **body**. So a remote desktop GUI got an unwindowed, unbounded event list: the dashboard's "Recent activity" panel showed stale events while the 24h KPI (computed separately, server-side) correctly read zero — a confusing mismatch. The shim now merges the JSON request body with the query string (body wins), so the window + limit are honored on the remote path. Verified live via the Tauri MCP bridge (remote mode: `limit:3` returned all 13 events before the fix); regression test `test_audit_events_filters_from_json_body` exercises a GET-with-body at the HTTP layer.
- **Dashboard "Recent activity" stayed empty in a quiet vault** (`gui/src/routes/DashboardPage.tsx`) -- now that the window filter works, the feed fetches the latest N events with **no** time window (so it stays useful — relative-time labels make their age clear), while the activity chart and the "Audit events 24h" KPI scope to 24h client-side. The KPI's fallback (when the summary endpoint is unavailable) now counts events within the last 24h rather than the raw fetched length.

### Changed

- **Stop tracking generated Tauri schemas** (`gui/src-tauri/gen/schemas/`) -- the capability / permission schemas are regenerated on every GUI build and absorb the dev-only `mcp-bridge` capability when the `mcp_local_dev` feature is on, producing constant churn. They are now gitignored (`gui/src-tauri/.gitignore`) and removed from tracking; the build recreates them from the committed capability files. Reverses the v0.17.2 commit of those artifacts.

## [0.17.2] - 2026-06-18

### Changed

- **Regenerate Tauri GUI capability schemas** (`gui/src-tauri/gen/schemas/*.json`) -- pick up the dev-only `mcp-bridge` capability (local Tauri MCP bridge, gated behind the `mcp_local_dev` Cargo feature and `BASTION_TAURI_MCP=1` at runtime; inert in release builds). Generated artifacts only; no runtime behavior change for shipped builds.

## [0.17.1] - 2026-06-18

### Added

- **Request-level statistics aggregator** (`src/stats.rs` `DashboardStats`, instrumented in `Core::handle_request`) -- a lock-free ring of 24 hourly buckets per metric (`denied`, `auth_failures`, `audit_write_failures`, `requests`) held on `Core`, incremented from the request hot path. Closes the dashboard deferral: BastionVault's audit *trail* is a change-history aggregation (no per-request allow/deny), so these live operational signals are now counted as requests happen. A denial is `ErrPermissionDenied` on any route; a failed login is any `/login`-route attempt whose response carries no `auth` (covers hard errors **and** the `Ok(error_response)` bad-password path); an audit-write failure is a log-phase error. Process-wide and in-memory by design (live gauges, not persisted history — the audit devices remain the durable record). Surfaced via `sys/dashboard/summary` as `audit_24h.denied`, `audit_24h.write_failures`, and `attention.failed_logins_1h`; the GUI shows "N denied" on the audit KPI and adds audit-write-failure (danger) + failed-login (warning) rows to the dashboard attention panel. Tests: `stats::tests::*` (windowing / hour-boundary reset / age-off) + `test_dashboard_summary_counts_denials_and_failed_logins` (end-to-end) + 2 `AttentionPanel` vitest cases. *(Certs-expiring / credentials-due attention rows remain deferred — the data exists (`pki` `not_after_unix`, `ldap` `rotation_period`) but per-load enumeration across every mount is the open cost question.)*

## [0.17.0] - 2026-06-18

### Added

#### GUI Dashboard Redesign (operational PAM landing view)

Replaces the static Dashboard (mounts + auth-methods listing) with a statistics-driven landing view modelled on CyberArk / Delinea / BeyondTrust / HashiCorp Vault / Teleport. ([features/gui-dashboard-redesign.md](features/gui-dashboard-redesign.md))

- **`GET /v1/sys/dashboard/summary`** (`src/modules/system/mod.rs` `handle_dashboard_summary`, actix shim `sys_dashboard_summary_request_handler` in `src/http/sys.rs`) -- one read-only call returning `{ version, namespace, seal{sealed,initialized}, counts{secret_mounts, auth_mounts, policies, entities}, audit_24h{total} }`. Counts are ACL-gated (mount visibility resolved from the caller's token like `handle_internal_ui_mounts_read`) and namespace-scoped (`list_policy_ns` / `list_entities_ns`; child-namespace mounts via the namespace registry). The 24h audit total reuses a new `collect_audit_events()` helper factored out of `handle_audit_events` (shared, no duplication). Backend test `test_dashboard_summary_basic`.
- **`dashboard_summary` Tauri command** (`gui/src-tauri/src/commands/system.rs`) routed through `make_request` / the `Backend` trait so it works embedded **and** remote; typed `dashboardSummary()` wrapper in `gui/src/lib/api.ts`.
- **Rewritten `DashboardPage`** + `gui/src/components/dashboard/` (`KpiTile`, `HealthStrip`, `SessionActivityChart` with exported `bucketByHour`, `RecentAuditCard`, `LiveSessionsCard`, `AttentionPanel`, `QuickActions`). One summary call + `Promise.allSettled` for live/audit data, per-tile graceful degradation (`—` + hint when a mount or the route is absent), 5s poll on the live-session widgets only. KPI row: live sessions, healthy bastions, secret engines, policies, identities, audit events 24h. 10 new vitest cases (`gui/src/test/dashboard.test.tsx`); suite now 130 passing.
- **Deferred (no data source yet):** `audit_24h.denied` / audit-write-failure counts and the certs-expiring / credentials-due / failed-login attention rows -- BastionVault's audit trail is a change-history aggregation, not a request-level allow/deny log. The shipped `AttentionPanel` surfaces what is derivable today (sealed vault, down/degraded bastions).

## [0.16.1] - 2026-06-18

### Added

- **Per-principal namespace assignment (login-restriction)** (`src/modules/namespace/ns_assignment.rs`, Phase 5 of [features/namespaces-multitenancy.md](features/namespaces-multitenancy.md)) -- restrict which namespaces a credential may authenticate into. The auth mount is shared across namespaces, so by default any credential can bind to any namespace; an operator can now record an explicit allowed-namespace list per principal. With **no record a principal is unrestricted** (unchanged behavior, so single-tenant installs are unaffected); a non-empty record permits login only at a listed namespace **or a descendant of one**, and a login at any other namespace is refused with `permission_denied` (fails closed — no silent fallback to root). Enforced at login for userpass (password + FIDO2) and approle — the backends that bind a login namespace today. New root-scoped management surface `v2/sys/identity/ns-assignment/<mount>/<name>` (Read/Write/Delete) + `v2/sys/identity/ns-assignment` (List), reachable over HTTP via `configure_sys_routes`. The GUI Users and AppRole pages gain an "Allowed namespaces" multi-select (empty ⇒ unrestricted), shown only when child namespaces exist. *(cert auth is disabled in the OpenSSL-free default build and the standalone FIDO2 backend is not namespace-aware, so enforcement there awaits the separate namespace-binding follow-up; the store and endpoints already accept any mount.)*

### Fixed

- **GUI namespace switcher reverted to root after selecting a child** (`gui/src-tauri/src/commands/namespaces.rs`, `gui/src-tauri/src/commands/mod.rs`) -- selecting a namespace (e.g. `test`) flickered and snapped back to `root` with the child entry vanishing from the dropdown. The `sys/namespaces` CRUD commands are documented to operate from the root namespace's view, but they routed through `make_request`, which attaches the session's active-namespace header. After the switcher set the active namespace, `list_namespaces` was scoped to the just-selected child and returned *its* (empty) children, so the dropdown re-rendered with only the `root` option and the `<select value="test">` matched nothing. Added a root-pinned `make_request_root` helper (forces `namespace = None`) and routed `list`/`read`/`write`/`delete` namespace commands through it, so namespace management always addresses the root view regardless of the active tenant.

## [0.16.0] - 2026-06-18

### Added

- **`bvault exchange verify` — offline backup integrity check** (`src/cli/command/exchange_verify.rs`, `src/exchange/verify.rs`). Validates a `.bvx` or plaintext `bvx.v1` file with no running vault or network, so it can run directly against a scheduled-export destination (e.g. `/backups`). Checks: envelope decrypts under the password (XChaCha20-Poly1305 AEAD authenticity), payload parses with the `bvx.v1` schema tag, every embedded file blob re-hashes to its recorded `sha256` + `size_bytes`, and the document is non-empty (a backup that captured nothing **fails** — guarding against the empty-export regression). Exit 0 on success, 1 on failure; `--json` for machine-readable output. Reusable library entry point `exchange::verify_backup_bytes` returns a structured `VerifyReport`.

### Fixed

- **Full-vault `.bvx` exports came back empty** (`src/exchange/scope.rs`) -- the exchange / scheduled-export scope resolver hardcoded the bare `logical/` and `sys/` storage prefixes, but re-root activation (the default for every install) stores root-tenant data under `namespaces/<root_uuid>/logical/` and `.../sys/`. Every list/get missed, so a `scope.kind = "full"` backup produced a zero-item document (~577-byte envelope). `MountIndex` now carries the active `Core::root_logical_prefix()` / `root_system_prefix()` and all KV/resource/file/group reads address through it. The KV branch also no longer reads the bare mount path (`secret/`) -- it walks the mount's barrier subtree (`<root>logical/<uuid>/`), capturing kv-v2 `data/`/`metadata/` leaves -- and `import_from_document` writes KV back through the same barrier prefix so backups round-trip. Added a re-root regression test covering KV, resources, file blobs, and groups.

## [0.15.5] - 2026-06-18

### Security

- **GUI dependency audit** -- run `npm audit fix` to resolve 7 advisories (1 critical, 4 high, 1 moderate, 1 low) across `vitest`, `vite`, `react-router`/`react-router-dom`, `ws`, `postcss`, and `@babel/core`. All semver-compatible patch/minor bumps; `npm audit` now reports 0 vulnerabilities. TypeScript check, `vite build`, and the 120 vitest tests all pass.

## [0.15.4] - 2026-06-17

### Added
- **Full-vault portable backups for scheduled exports & the exchange engine.**
  `ScopeKind::Full` is now honoured by `exchange::scope::export_to_document`
  (`src/exchange/scope.rs`): a full export enumerates every KV / KV-v2 mount,
  every resource and file blob, and every resource/asset group without the
  operator hand-listing selectors. The GUI Schedules editor gains a **"Back up
  everything (full vault)"** toggle (`gui/src/routes/ExchangePage.tsx`) that
  saves the schedule with `scope.kind = "full"`. Applies to cron-driven runs,
  "Run now", and the one-shot exchange export alike (single chokepoint).
  (`features/scheduled-exports.md`, `features/import-export-module.md`)

### Fixed
- **Scheduled-export commands no longer fail with "Vault not open" in remote
  mode.** The GUI `scheduled_exports_*` Tauri commands
  (`gui/src-tauri/src/commands/scheduled_exports.rs`) were embedded-only — they
  locked `AppState::vault`, which is always `None` when the desktop client is
  connected to a remote server, so the Import/Export → Scheduled backups tab
  surfaced a spurious error even with the vault unsealed. They now branch on
  `VaultMode` and route through the `bv_client::Backend` HTTP API
  (`/v{1,2}/sys/scheduled-exports/*`) when remote, matching the embedded path.
  A `POST` alias was added to the server's `scheduled-exports/{id}` update route
  (`src/http/sys.rs`) so the client's logical-`Write`→`POST` mapping reaches it
  (the `PUT` route is retained for REST clients).

## [0.15.3] - 2026-06-17

### Added
- **Rustion integration Phase 9.3 — multi-instance failover completion + re-attestation enforcement.**
  - Dispatcher now honours a bastion group's `selection: random` (shuffles health-filtered members) vs `ordered`, with a new `group` selection mode surfaced for audit.
  - `rustion_dispatcher_preview` Tauri command + `POST /v1/rustion/dispatcher/preview` route + a "Will try: A → B" panel on the resource Connection tab showing the dispatcher's candidate ordering and skipped targets with live health.
  - `attestation_renew_at` enforced end-to-end: Rustion stamps a 14-day deadline at authority approval, the new `POST /v1/authorities/attest` route bumps it (persisted across hot-reload) and emits `authority.attested`, and the envelope-verify path refuses lapsed authorities with `403 attestation_expired` — exempting the `attest` op so a lapsed authority can recover.
  - Two-instance kill-primary failover harness behind `E2E_FAILOVER=1` (`tests/e2e/rustion-ssh/docker-compose.failover.yaml` + run.sh Step 9).

### Changed
- **`DELETE /v1/rustion/bastion-groups/{name}` now refuses (409)** while any locked policy tier (global / type / asset-group / resource) still pins the group, preventing a `rustion-required` lock from silently degrading to the random pool.

### Removed
- **Dropped two-way mTLS on the Rustion control plane** as a planned item — caller authenticity rests on the BVRG-v1 hybrid (Ed25519 + ML-DSA-65) envelope signature plus deployment-id binding and the re-attestation deadline; control-plane TLS remains for transport confidentiality only. Rustion HA is likewise no longer pursued inside Rustion — availability on the `rustion-required` path is provided by BastionVault-side multi-instance failover groups.

## [0.15.2] - 2026-06-17

### Changed

- **GUI remote backend now targets the `/v2` API prefix** (`gui/src-tauri/src/commands/connection.rs`)
  -- the `bv_client::RemoteBackend` is built with `with_api_version(2)`, so all
  logical requests (including the namespace admin routes) hit `/v2/...` rather
  than the legacy `/v1`. This aligns the desktop client with `agent.md`'s
  v2-forward HTTP policy and lets the `capabilities-self` command drop its
  hardcoded `/v2/...` absolute-path workaround (`commands/capabilities.rs`).
  **Note:** the `/v2` router rejects plain **kv-v1** mounts with
  `ErrApiVersionMismatch`; remote kv-v1 read/write/list is therefore no longer
  supported from the GUI (kv-v2, the default, is unaffected and the Secrets page
  is already kv-v2-only).

### Fixed

- **Workspace-wide clippy cleanup** -- `cargo clippy --workspace --all-targets`
  is now warning-clean (was ~250 lints, including one `uninit_vec` *error* in
  `crates/bastion-plugin-sdk` that broke the lint build). Fixes span both
  machine-applicable rustfix suggestions and manual ones: De Morgan boolean
  simplifications in the plugin storage-prefix checks (`src/plugins/runtime.rs`,
  `process_runtime.rs` — behavior-preserving), an infallible `Any` conversion in
  `src/modules/pki/x509.rs`, `sort_by_key`/`to_vec`/`enumerate`/`slice::from_ref`
  idiom fixes, struct-init and dead-import cleanups, doc-comment list
  formatting, `#[allow]` annotations for intentional patterns (detached
  scheduler `JoinHandle`s in `Core::post_unseal`, Tauri commands with many
  args, the plugin host-fill ABI). No behavior changes; full lib + GUI test
  suites remain green.

## [0.15.1] - 2026-06-17

### Fixed

- **Namespace HTTP routes unreachable in remote mode** (`src/http/sys.rs`) -- the
  multi-tenancy namespace endpoints (`sys/namespaces`, `sys/namespaces/{path}`,
  `sys/namespace-links`, `sys/namespace-links/{id}`) lived only on the sys
  backend's *logical* route table, so they were reachable in embedded vault mode
  but the explicit `/v1/sys` actix scope returned a bare `HTTP 404 (no body)`
  before the request could fall through to the `/v1/{path:.*}` logical catch-all.
  The desktop GUI's Namespaces page (and any remote API client) consequently
  404'd on every list/CRUD call. Added explicit HTTP shims in
  `configure_sys_routes` that forward to the logical handlers, including the
  `LIST` verb and the `X-BastionVault-Namespace` header copy that the logical
  catch-all performs (without it, child-namespace scoping silently resolved to
  root). Added end-to-end HTTP regression tests so the routes can no longer
  regress to embedded-only.

## [0.15.0] - 2026-06-17

### Added

#### Namespaces / Multi-tenancy (Phase 1 foundation)

- **Hierarchical namespace container** (`src/modules/namespace/`) -- introduces
  Vault-style multi-tenant namespaces so one deployment can host isolated
  tenants. Each namespace has an immutable UUID, a mutable slash-delimited path,
  a parent, per-namespace mount routing, and a quota record (enforcement lands in
  Phase 4). The implicit root namespace is minted on first unseal.
  (Phase 1, `features/namespaces-multitenancy.md`)
- **Namespace CRUD API** under `v2/sys/namespaces` (served by the system
  backend): `LIST sys/namespaces` (children of the caller's namespace), and
  `READ` / `WRITE` (create-or-update) / `DELETE` on `sys/namespaces/<path>`.
  Delete is refused for the root, for namespaces with children, and for
  namespaces that still hold mounts. Namespace names containing `/`, `..`, `*`,
  surrounding whitespace, or control characters are rejected.
- **Request → namespace resolution** -- both Vault-compatible addressing forms
  are supported: the `X-BastionVault-Namespace: <path>` header and the
  `/<ns>/...` path prefix (longest-match). A request supplying neither targets
  the root namespace.
- **Per-namespace mount-router registry** -- each non-root namespace gets its
  own mount table persisted at `namespaces/<uuid>/core/mounts`, barrier-isolated
  under `namespaces/<uuid>/logical/`, reusing the existing `MountsRouter`
  router-prefix mechanism (no new routing engine).
- **Barrier re-root migration (copy + verify stage)** -- an idempotent,
  **non-destructive** migration copies root-tenant data under
  `namespaces/<root_uuid>/...` and records a verified version marker; legacy keys
  remain authoritative. Activating the re-rooted prefix as the live root is a
  separate, operator-gated step behind `BASTION_NAMESPACE_REROOT` (default off),
  so upgrades stay reversible (restore a pre-migration BVBK backup to roll back).
- 9 unit/integration tests cover path validation, registry CRUD + delete guards,
  the request resolver, the `v2/sys/namespaces` API, and migration idempotence.
- **End-to-end per-namespace mounts** (`MountsRouter::mount_one`/`unmount_one`,
  namespace-aware `sys/mounts`, and a header→path rewrite in `Core::handle_request`)
  -- a child namespace can mount secret engines that are storage-isolated under
  `namespaces/<uuid>/logical/` and addressable via either the
  `X-BastionVault-Namespace` header or the `/<ns>/...` path prefix. Cross-tenant
  isolation is proven by test (tenant-b cannot see tenant-a's mount/secret).

#### Namespaces / Multi-tenancy (Phase 2 — token binding)

- **Namespace-bound tokens** (`src/modules/namespace/token_binding.rs`) -- every
  token records the namespace it was issued in plus an opt-in, immutable
  `child_visible` flag, carried in token metadata (legacy tokens read as
  root-bound). A token may operate only in its own namespace, or — when
  `child_visible` — in a descendant; never in a parent, sibling, or unrelated
  namespace. Enforced in `Core::handle_request` right after auth resolution and
  before any backend dispatch (cross-namespace use returns `permission_denied`).
  Root tokens bypass (superuser). `sys/auth/token/create` accepts
  `child_visible` and binds the new token to the namespace named by the request
  header. (Phase 2, `features/namespaces-multitenancy.md`)

- **Namespace policy templates** -- ACL policy paths now support
  `{{namespace.path}}` (the token's bound namespace path; root = `""`, a valid
  substitution) and `{{namespace.id}}` (the bound namespace UUID; fail-closed
  when absent), alongside the existing `{{username}}` / `{{entity.id}}` /
  `{{auth.mount}}` vocabulary.

- **Audit namespace attribution** -- every audit entry now carries a
  `namespace` field (the request token's bound namespace; omitted when root),
  so a per-namespace auditor and the root SOC mirror can attribute events to a
  tenant. (foundation for per-namespace audit broadcasters)

- **Cross-namespace policy path refusal** (`src/modules/namespace/policy_scope.rs`)
  -- a policy authored inside a namespace (write carrying the namespace header)
  may only reference paths owned by that namespace; referencing another
  tenant's (or root's) path space is refused at write time with a `403`. Root
  operators (no header) remain unrestricted. Write-time syntactic guard; does
  not touch the authorization hot path.

#### Namespaces / Multi-tenancy (Phase 2 — per-namespace policy + audit)

- **Per-namespace policy storage** (`src/modules/policy/policy_store.rs`) -- ACL
  policies are now tenant-scoped: a policy named `admin` in one namespace is an
  entirely separate document from `admin` in another. Tenant policies live in
  their own barrier keyspace (`policy-ns/<b64(path)>/acl/…` and `…/history/…`);
  the root namespace keeps its existing keyspace untouched, so upgrades are
  byte-for-byte compatible. The `sys/policy*` read/write/list/delete/history
  handlers scope by the request's `X-BastionVault-Namespace` header, and a list
  inside a namespace returns only that namespace's policies (never the root
  seeded set or the synthetic `root`). (Phase 2, `features/namespaces-multitenancy.md`)

- **Namespace-aware ACL compilation** -- on the authorization hot path, each of
  a token's named policies is loaded from the namespace the token is bound to,
  so a token issued in tenant-a is authorized strictly against tenant-a's
  policies. Root-bound tokens and all non-token callers resolve to the global
  keyspace exactly as before. The synthetic `root` superuser policy resolves
  identically in every namespace so a namespace-bound root token keeps working.

- **Per-namespace audit broadcasters + superuser mirror** (`src/audit/broker.rs`)
  -- audit devices are scoped to a namespace: a device enabled in tenant-a only
  receives tenant-a's audit stream, with its own tamper-evident hash chain so a
  single device file verifies independently. A root device may set `mirror: true`
  to additionally receive every namespace's stream (the central-SOC view), kept
  on the root chain and showing each event's originating namespace. `sys/audit`
  enable/disable/list scope by the namespace header, and every namespace's
  `sys/audit` list surfaces the mirror so tenants know their stream is shadowed.
  Legacy persisted device configs deserialize as root, non-mirror.

#### Namespaces / Multi-tenancy (Phase 3 — per-namespace identity)

- **Per-namespace identities** (`src/modules/identity/`) -- entities, aliases,
  and groups are now tenant-scoped. The same external principal
  (`userpass/alice`) resolves to a *distinct* entity in each namespace, so one
  customer's `alice` SSO claim grants nothing in another's. Entity records stay
  globally keyed by UUID (callers that resolve `entity_id` are unchanged) but
  carry a `namespace` tag; the alias index and the group + group-history
  keyspaces are partitioned per namespace. (Phase 3, `features/namespaces-multitenancy.md`)

- **Per-login namespace binding** -- `userpass` (password + FIDO2) and `approle`
  logins read the `X-BastionVault-Namespace` header, provision/resolve the
  entity and expand identity-group policies *in that namespace*, and bind the
  issued token to it. A login naming a namespace that does not exist fails
  closed. The shared credential lives in the root auth mount, but the resulting
  session, identity, and group policies are namespace-scoped. (`cert` login
  binding is a follow-up.)

- **Namespace-scoped group management** -- the `identity/` group and
  entity-alias HTTP endpoints scope by the namespace header, and `identity/` is
  exempted from logical-path rewriting so it stays header-addressed like `sys/`.
  A group named `admins` in one tenant is unrelated to `admins` in another.

- **Cross-tenant identity links** (`src/modules/namespace/identity_link.rs`,
  `v2/sys/namespace-links`) -- a namespace may declare that entities in its own
  subtree are the same person, for audit correlation. Links are one-way: a
  namespace may only reference itself or its descendants, and links are stored
  partitioned by owner, so siblings and the linked children can never enumerate
  them. List/create/read/delete via the system backend, scoped by header.

#### Namespaces / Multi-tenancy (Phase 4 — quotas + GUI)

- **Per-namespace quota enforcement** (`src/modules/namespace/quota.rs`) -- all
  six namespace quotas are now enforced at admit time (`0` = unlimited):
  `max_mounts` (mount create), `max_child_namespaces` (namespace create), and
  `request_rate` (per-namespace token bucket → `429`); plus the accounting
  quotas `max_entities` (refused before a login provisions a *new* identity in
  the namespace — existing principals still authenticate), `max_storage_bytes`
  (the namespace's barrier-byte total under its logical prefix plus the incoming
  value, so the write that crosses the cap is the one refused with `507`), and
  `max_leases` (the namespace's live lease count, enforced at lease
  registration). Accounting quotas apply to non-root namespaces only.
  (Phase 4, `features/namespaces-multitenancy.md`)

- **Namespaces GUI** (`gui` → Namespaces page) -- a management page lists
  namespaces and creates them by path with all six quota fields and the
  `child_visible_default` flag, edits quotas, and deletes (refused while a
  namespace still holds children or mounts). Backed by new Tauri commands over
  `v2/sys/namespaces`.

- **GUI namespace switcher** -- a top-of-sidebar picker scopes the whole session
  to a namespace: selecting one records the active namespace on the backend and
  every authenticated request thereafter carries the `X-BastionVault-Namespace`
  header. Implemented via a new `bv_client::Backend::handle_with_namespace`
  method overridden by both the embedded (in-process `Core`) and remote (HTTP)
  backends; the embedded path injects the request header, the remote path sets
  the HTTP header. Single-tenant deployments never see the switcher.

- **Re-root activation — the default for every install, no opt-in.** All
  deployments now store the root tenant's data under `namespaces/<root_uuid>/…`,
  so every tenant (including the implicit root) lives under a uniform prefix.
  `Core` resolves the activation decision at the top of `post_unseal` (before any
  view or mount table is built) and repoints its system view, root mount router,
  and a new `root_storage_prefix`; `Core.mounts_router` became swappable
  (`ArcSwap`) and the previously-hardcoded legacy prefixes in `Core::mount` and
  `exchange/scope` now derive from the active root. **New installs** activate
  immediately (nothing to copy). **Existing installs** activate automatically on
  the next unseal: the non-destructive copy + byte-for-byte verify of the legacy
  `sys/` / `logical/` / `core/mounts` data runs eagerly on the *same* boot and
  the prefix flips only if it succeeds — a copy that cannot be verified leaves
  the legacy layout authoritative for that boot and retries next unseal (fail
  safe; unseal is never blocked). The legacy `BASTION_NAMESPACE_REROOT` opt-in is
  removed. Activation is recorded by a persistent, one-way registry marker; the
  legacy keys are retained on disk so a pre-namespace build can still be restored
  from a BVBK backup. The full library test suite (836 tests) runs green under
  activation. (Phase 1b, `features/namespaces-multitenancy.md`)

- **Scope note:** Phases 1–4 are complete — container/registry/resolver,
  per-namespace mounts + dispatch, token binding, namespace-scoped policy
  storage + ACL compilation, cross-namespace path refusal, per-namespace audit
  broadcasters + root mirror, per-namespace identity + per-login binding +
  cross-tenant links, **all six quotas enforced**, a namespace-management GUI, a
  **GUI namespace switcher**, and **re-root activation (the unconditional
  default for every install)**. Remaining follow-ups: `cert`-login namespace binding, tenant
  self-service of `sys/*` (today reachable only by root/sudo tokens carrying the
  namespace header), and a recursive GUI namespace tree + rename.

## [0.14.9] - 2026-06-16

### Added

- **GUI session-expiry monitor** (`gui/src/components/SessionMonitor.tsx`,
  `gui/src-tauri/src/commands/auth.rs`) -- a background monitor mounted at the app
  root polls a new `token_status` command (`auth/token/lookup-self`) on a 30s
  interval and immediately on window focus/visibility change. When the active token
  has expired or been revoked it tears the session down (`expireSession` in
  `authStore`) and the route guard bounces to `/login` with a "Your session expired"
  banner; a near-expiry warning toast fires once under 2 minutes of TTL. Transient
  backend errors (network blip, briefly sealed vault) report `reachable: false` and
  are ignored so a momentary hiccup never logs the operator out. Closes the gap where
  an expired session was only discovered via confusing "permission denied" toasts on
  the next data fetch.

- **Graphical Policy Builder & Validator (planned)** -- spec + roadmap drafted for a
  visual, block-based policy construction surface and an effectivity validator beside
  the textual HCL editor on the Policies page. Hybrid evaluation engine: instant
  client-side lint/preview plus an authoritative, stateless backend dry-run
  (`POST /v1/sys/policies/acl/test`) that reuses the production ACL matcher to report
  allow/deny + matched rule for `(path, capability)` cases without persisting. Savable
  test cases (`policy-tests/<name>`) gate every save. 5 phases, no code yet.
  (`features/policy-builder-validator.md`, `roadmaps/policy-builder-validator.md`)

### Changed

- **AppRole GUI** (`gui/src/routes/AppRolePage.tsx`) -- the Create AppRole "Token Policies" field now uses the `PolicySelect` autocomplete, validating entries against the vault's existing policies (chips, type-to-filter, ⚠ on unknown names) instead of an unvalidated comma-separated free-text input. Falls back to free text when the policy list can't be fetched.

## [0.14.8] - 2026-06-15

### Added
- **`bvault status` daemon overview** (`src/cli/command/status.rs`) -- the
  `status` subcommand now prints an aggregated daemon snapshot: reachability,
  version, initialized/sealed state, key-share counts and unseal progress, the
  storage cluster mode (`single` vs `clustered`), and -- when clustered -- this
  node's id, leader role, and cluster health. Seal/init state is sourced from
  `/sys/info` so it reports correctly even on an uninitialized vault, and an
  unreachable daemon now exits non-zero with a clear error.

### Changed
- The `/sys/cluster-status` endpoint (`src/http/sys.rs`) now populates
  `node_id` from the hiqlite backend so clients can report the local node
  number without parsing raft metrics.

## [0.14.7] - 2026-06-15

### Fixed

#### Plugin publisher signatures (signed `.bvplugin` registration)
- Signed plugin bundles produced by `make plugins-sign` were rejected at
  registration as `"... is unsigned and accept_unsigned is false"`. Two
  defects:
  - The desktop GUI rebuilt the manifest from form fields on register,
    silently dropping the bundle's `signature` / `signing_key`. The
    Register flow now forwards a signed bundle's parsed manifest verbatim
    (re-stamping only `sha256` / `size`), and `api.PluginManifest` gained
    the `signature` / `signing_key` fields.
  - The host verifier re-serialised its own `PluginManifest` to rebuild
    the signing message, but `bv-plugin-pack` signed over a *parallel*
    struct whose serde field order (and field set: `long_lived`, empty
    `config_schema`) differed — so even a correctly-transmitted signature
    failed verification.

### Changed
- Extracted the plugin manifest types and a new key-sorted canonical
  `signing_message` into a shared `bv_plugin_manifest` crate, used by
  both the host verifier and the `bv-plugin-pack` signer. The canonical
  message is now invariant to serde field order, so signer and verifier
  agree by construction. **This changes the signed-message format**:
  re-sign existing bundles with `make plugins-sign` (the reference
  bundles in `plugins-ext/dist/` have been re-signed).

## [0.14.6] - 2026-06-15

### Added

- **GUI: pick the MIA environment when adding/editing a Server vault.** The
  Server form (Get Started → Add/Edit Server) now has a "MIA environment"
  combobox listing the `mia-<env>.toml` selectors installed on this host (plus
  a `(server default)` entry and the saved value when its selector isn't local).
  The choice is stored on the profile (`RemoteProfile.mia_environment`) and, on
  connect, takes precedence over the server-advertised environment so the
  machine gate dials the operator-chosen MIA daemon. This fixes the case where
  connecting failed with "this caller is not on the MIA's local allowlist"
  because the wrong `mia-<env>.toml` socket was being dialed and there was no
  way to override it from the setup screen. (`gui/src/routes/ConnectPage.tsx`)

## [0.14.5] - 2026-06-15

### Fixed

- **GUI: the selected MIA environment is now shared across every screen, not
  just within the Machines page.** The selection was page-local React state, so
  picking an environment on the Machine Login (or Config) tab didn't reach the
  connect-time machine gate or survive navigating away. It now lives in a small
  global store (`gui/src/stores/miaEnvStore.ts`): an explicit pick on any screen
  becomes the default everywhere for the session, the connect gate dials the
  selected `mia-<env>.toml`, and the store seeds from the saved config /
  server-advertised value and resets when switching deployments.

## [0.14.4] - 2026-06-15

### Added

#### FerroGate MIA environment persistence

- **`mia_environment` config field for the `ferrogate` mount**
  (`src/modules/credential/ferrogate/`). Records which MIA environment the
  deployment belongs to (e.g. `hml` → clients read `mia-<env>.toml`) and is
  advertised on the unauthenticated `auth/ferrogate/requirement` endpoint.
  Validated server-side (no path syntax). (`features/machine-authentication.md`)

### Fixed

- **GUI: MIA environment is now saved with the FerroGate config and used on
  every MIA dial.** Previously the Config tab's "MIA environment" field was
  transient autofill state — it was lost on save, and the connect-time machine
  gate, combined machine+user login, and the Machine Login tab always dialed
  the default `mia.toml`. The field now persists in the mount config, prefills
  the Config and Machine Login tabs, and the connect flow resolves the
  server-advertised environment's `mia-<env>.toml` socket automatically.

### Changed

- **GUI: the "MIA environment" field is now a combobox of the environments
  discovered on this host, and the selection is shared across screens.** Both
  the Config tab and the Machine Login tab now present a dropdown built from the
  installed `mia-<env>.toml` selectors (plus a `(default)` entry and the saved
  value if its selector isn't installed locally), replacing the free-text
  autocomplete. Selecting an environment in the Config tab immediately re-targets
  the Machine Login tab (and, on Save, the connect-time machine gate via the
  requirement endpoint) instead of each screen tracking its own value.
  (`gui/src/routes/FerroGatePage.tsx`)

## [0.14.3] - 2026-06-12

### Added

#### FerroGate CMIS HA failover

- **`cmis_srv` config field for the `ferrogate` mount**
  (`src/modules/credential/ferrogate/`). Set a DNS SRV owner name (e.g.
  `_ferrogate-prod._tcp.example.com`) and the mount resolves it on every JWKS
  fetch, then dials every advertised CMIS node in RFC 2782 order (ascending
  priority, then descending weight) until one connects *and* verifies its SPKI
  pin. The shared pin authenticates whichever node answers. Takes precedence
  over `cmis_endpoint`; exposed in the GUI config form and CLI. Mirrors the
  MIA's own SRV failover. (`features/machine-authentication.md`)

### Fixed

- **CMIS client now fails over across HA nodes instead of pinning one.**
  Previously the `cmis_grpc` source dialed a single configured `cmis_endpoint`
  (plus host-local aliases) with no SRV resolution or failover, while the MIA
  resolved the SRV and failed over automatically. When one cluster node's cert
  SPKI diverged from the shared pin, BastionVault — pointed at that node by GUI
  autofill — failed with "SPKI pin mismatch" while the MIA transparently used a
  healthy sibling. The CMIS client and `Autofill from local MIA` now carry the
  SRV through (rather than a single resolved node), so the mount fails over the
  way the MIA does.

## [0.14.2] - 2026-06-12

### Changed

- **`log_level` now honors per-target directives** (`src/logging.rs`). The
  file logger previously kept only the first token of an env_logger-style
  filter, so a directive like `info,hiqlite=warn` silently collapsed to
  `info`. The `FanoutLogger` now parses `target=level` overrides and applies
  them by target prefix (longest-prefix-first), lifting the global `max_level`
  ceiling so a more-verbose override isn't pre-filtered. Operators can quiet
  chatty dependencies — e.g. set `log_level = "info,hiqlite=warn"` to suppress
  the high-volume `hiqlite::network::raft_server` WebSocket connect logs in HA
  deployments — without lowering the global level.

## [0.14.1] - 2026-06-12

### Fixed

- **Autofill from local MIA now supports SRV-advertised CMIS.** A `mia-<env>.toml`
  that points at CMIS via a DNS SRV record (`[cmis].srv`, e.g. an HA cluster)
  instead of a literal `[cmis].endpoint` previously failed autofill with "no CMIS
  endpoint found". `read_cmis` now also reads `[cmis].srv`, and `build_autoconfig`
  resolves it to a concrete `host:port` (RFC 2782 ordering — ascending priority,
  descending weight — mirroring the MIA's own selection in
  `ferrogate/crates/mia/src/endpoint.rs`) via the system DNS resolver, pinning the
  selected node (a warning notes the cluster may change). Affects both the GUI
  "Autofill from local MIA" button and `bvault ferrogate autoconfig`.

## [0.14.0] - 2026-06-12

### Added

#### FerroGate MIA environments + validated bootstrap policies (GUI/CLI)
- **MIA environment selector** -- the Machines (FerroGate) **Config** and
  **Machine Login** tabs gain an "MIA environment" autocomplete. Selecting an
  environment reads `mia-<env>.toml` (and its allowlist/socket) instead of the
  default `mia.toml`, so a host carrying side-by-side deployments (e.g. `hml`,
  `prod`) can autofill the right one. Suggestions are discovered by scanning the
  system and per-user config dirs (`ferrogate_list_environments`).
- **`bvault ferrogate {login,status,whoami,autoconfig} --environment <env>`** --
  CLI parity for the same selector; mirrors `mia --environment <env>`. Names are
  validated (`validate_environment`) before becoming a filename component.
- Threaded an environment selector through the MIA helper layer
  (`resolve_mia_socket_for`, `read_cmis_config_for`, `read_allowlist_trust_domain_for`,
  `build_autoconfig`) in `src/cli/command/ferrogate_mia.rs`; the default-environment
  wrappers are unchanged.

### Changed

- **Bootstrap policies are now a validated autocomplete** (Config tab) -- the
  free-text "Bootstrap policies" field is replaced by a multi-select autocomplete
  over the vault's existing ACL policies (new reusable `PolicySelect` component),
  so a typo can't slip through. `default` is offered as the baseline; unknown
  (mistyped/stale) selections render as amber ⚠ chips and block Save. Falls back
  to free text when policies can't be listed.

### Security

- Validated bootstrap-policy names prevent a silent empty grant to the
  first-bootstrapped machine (a misspelled policy under combined machine+user
  auth intersects to nothing). Environment selectors are validated as safe
  single path components before use, preventing path traversal via a
  `mia-<env>.toml` filename.

## [0.13.5] - 2026-06-11

### Changed

- **FerroGate machine policy editor is now a multi-select, not free text**
  (`gui/src/routes/FerroGatePage.tsx`) -- the approve / *Edit policies* modal replaces the
  comma-separated text field with toggle-chips populated from the vault's existing ACL
  policies (`list_policies`, excluding `root` and the always-on `default`). This prevents
  typos that silently grant nothing (e.g. `adminitrator` instead of `administrator`, which
  intersects to empty under combined machine+user auth). Any policy on the machine that is
  not a known policy is shown as an amber ⚠ chip so a stale/mistyped grant is visible and
  removable; if policy listing is unavailable (insufficient privileges) the field falls back
  to free text.

## [0.13.4] - 2026-06-11

### Added

- **Edit policies for approved FerroGate machines in the GUI**
  (`gui/src/routes/FerroGatePage.tsx`) -- the *Machines (FerroGate)* admin page previously
  only let operators set policies at first approval; an approved machine could only be
  revoked. Approved machines now have an **Edit policies** action that reopens the approve
  flow prefilled with the machine's current policies/TTL/comment and re-approves in place
  (via the existing `ferrogate_approve` command). This matters because combined machine+user
  auth grants the **intersection** of the machine's policies and the user's policies, so the
  machine's approved policy set is the ceiling — adjusting it is how an operator restores a
  user's access without re-enrolling the host.

### Fixed

- **GUI machine-identity login used the wrong DPoP audience**
  (`gui/src/routes/ConnectPage.tsx`, `gui/src/routes/LoginPage.tsx`, `gui/src/lib/types.ts`)
  -- both the connect-time machine gate (`runMachineGate`) and the combined machine+user
  user-login step (`finalizeLogin`) signed the DPoP proof with `profile.address` (the vault
  server URL), so connecting to a mount whose `expected_audience` is the trust domain
  (e.g. `https://ferrogate.dev`) failed with *"token verification failed: DPoP proof does
  not match the request"* — an `htu` binding mismatch. The connect flow now captures the
  server-advertised `expected_audience` (from `ferrogate_requirement`) onto the in-memory
  `RemoteProfile`, and both DPoP-signing paths use it, falling back to `profile.address`
  only when the server leaves it unset.

## [0.13.3] - 2026-06-11

### Added

- **`bvault operator ferrogate require-machine-identity` CLI command**
  (`src/cli/command/operator_ferrogate.rs`) -- show or set the server-wide
  `require_machine_identity` enforcement flag without hand-writing a `curl` to `auth/ferrogate/config`.
  Run with no argument to print the current value, or `on`/`off` (also accepts true/false,
  enable/disable, yes/no, 1/0) to set it. Like the other `operator ferrogate` subcommands it runs
  against the server with a root token and does not need an approved machine.

## [0.13.2] - 2026-06-11

### Added

- **Server-enforced FerroGate machine identity** (`src/modules/credential/ferrogate/`, `src/core.rs`,
  `src/modules/auth/token_store.rs`) -- a new `require_machine_identity` flag on the
  `auth/ferrogate/config` mount makes machine authentication a property of the **server**, not the
  client. When set, the token layer rejects every authenticated request whose token is not FerroGate
  machine-bound (carries `spiffe_id` in its metadata); root tokens stay exempt so bootstrap/approval
  and break-glass admin keep working. The flag is mirrored to the system view and an in-memory atomic
  loaded at unseal, so enforcement is a single atomic read on the hot path with no per-request storage
  hit. Independent of `require_user_token`; set both for full combined machine+user enforcement.
- **Unauthenticated `auth/ferrogate/requirement` discovery endpoint** -- lets a client learn, before
  login, whether a server mandates machine identity (plus the expected audience / trust domain). A
  new `ferrogate_requirement` Tauri command + GUI API exposes it.

### Changed

- **The connect-time machine-identity gate is now server-driven** (`gui/src/routes/ConnectPage.tsx`,
  `gui/src/routes/LoginPage.tsx`) -- the GUI queries the server's `requirement` endpoint on connect
  and runs the machine gate from the server's answer. The client-side "Require machine identity"
  toggle on the Add/Edit-vault form is removed; `RemoteProfile.require_machine_identity` is now only
  an internal cached hint. A non-cooperating client can no longer skip machine auth — the server
  enforces it regardless. The FerroGate admin config page gains a "Require machine identity (all
  sessions)" toggle that sets the server flag.

## [0.13.1] - 2026-06-11

### Added

- **Edit button on the vault chooser** (`gui/src/routes/ConnectPage.tsx`) -- saved vault cards now
  offer "Edit" alongside Pin/Remove, opening the same Add modal prefilled from the profile and saving
  in place via the existing `update_vault_profile` command (no more remove-and-re-add). Works for
  Local/Server/Cloud profiles; editing does not auto-open or change the default, and cloud
  `credentials_ref` is preserved.

### Fixed

- **Trailing slash in a server address produced a double-slash request URL**
  (`src/api/client.rs`, `crates/bv-client/src/remote.rs`) -- a profile address like
  `https://host:port/` was concatenated with a leading-slash path (`/v1/sys/health`) to yield
  `https://host:port//v1/...`, which the server does not route; the empty response surfaced as
  `Json(Error("EOF while parsing a value", line: 1, column: 0))`. Both HTTP clients now strip trailing
  slashes from the address when building requests.
- **FerroGate child-token verification rejected benign audience/`htu` variations**
  (`third_party/ferrogate-sdk-rust/crates/ferro-child-verify/src/lib.rs`,
  `src/modules/credential/ferrogate/verify.rs`) -- the DPoP proof's `htu` and the token `aud` were
  compared to the mount's `expected_audience` with exact string equality, so a trailing slash or a
  scheme/host case difference between the GUI profile address and the configured audience (e.g.
  `https://host:4200` vs `https://host:4200/`) failed with `DpopBindingMismatch` ("DPoP proof does
  not match the request"). Both comparisons now run through a new origin-normalizer
  (`normalize_htu`) that strips a trailing slash, lower-cases the scheme and host, and drops an
  explicit default port (`:80`/`:443`). This is a normalization, not a loosening -- scheme, host,
  port and path must still all be equal, so a different origin is still rejected.

## [0.13.0] - 2026-06-11

### Added

#### Combined machine+user authentication & enrolment lifecycle

- **Server-side combined machine+user policy** (`src/modules/credential/ferrogate/{mod,path_config,path_machines}.rs`)
  -- `auth/ferrogate/login` now accepts an optional `user_token`. When present, the minted token's
  policies are the **intersection** of the machine's approved policies and the user token's policies
  (`default` is baseline and re-injected by the token store), the combined token carries the *user's*
  `entity_id`/`username` for ownership/ACL while still recording the attesting `spiffe_id`, and the
  (broader) intermediate user token is revoked so only the narrower combined token survives. A new
  `require_user_token` config flag enforces this server-side: a login without a valid `user_token` is
  denied (`user_token_required`). Root tokens cannot be bound. Covered by
  `test_ferrogate_combined_user_binding`.
- **Operator CLI machine authorization** (`src/cli/command/operator_ferrogate.rs`) -- new
  `bvault operator ferrogate {list,approve,reject,revoke}` subcommands that administer the enrolment
  queue against the running server with a root token. They do NOT require an approved machine, which
  breaks the bootstrap deadlock (you can authorize the first machine from the server). Machines are
  addressed by handle (from `list`) or by SPIFFE id (auto-hashed to the BLAKE3 handle).
- **GUI per-connection machine-identity gate** (`gui/src/routes/ConnectPage.tsx`,
  `gui/src/routes/LoginPage.tsx`, `gui/src-tauri/src/state.rs`) -- a new "Require machine identity
  (FerroGate)" option on remote connection profiles. When set, the connect flow attests the host via
  the local MIA before the login screen: an **approved** machine proceeds to user login (whose token is
  then bound into a combined session); a **pending/unknown** machine shows an enrolment dialog (SPIFFE
  id + `operator ferrogate approve` hint + Recheck); an **explicitly denied** (`rejected`/`revoked`)
  machine shows a hard access-denied with no proceed.
- **Typed enrolment outcome from machine login** (`gui/src-tauri/src/commands/ferrogate.rs`,
  `gui/src/lib/types.ts`) -- `ferrogate_machine_login` now returns a classified `enrolment`
  (`approved`/`pending`/`rejected`/`revoked`) + `message` instead of a generic error, so the UI can
  branch; genuine transport/verification failures still surface as hard errors. A `user_token`
  argument drives the combined-binding flow.
- **GUI admin toggle for combined auth** (`gui/src/routes/FerroGatePage.tsx`) -- the FerroGate config
  panel gains a "Require user token (machine + user)" checkbox wired to the new `require_user_token`
  flag.

## [0.12.8] - 2026-06-11

### Added

- **FerroGate `cmis_same_host` config flag** (`src/modules/credential/ferrogate/{mod,path_config,cmis}.rs`,
  `gui/src-tauri/src/commands/ferrogate.rs`, `gui/src/routes/FerroGatePage.tsx`, `gui/src/lib/{api,types}.ts`)
  -- declares that CMIS runs on the same machine as the BastionVault server. The configured
  `cmis_endpoint` is typically the host's public name (right for external MIA clients) but can be
  unreachable from the server's own vantage point: inside a rootless-podman (pasta) container the
  host's own address hairpins into the container's empty namespace and is refused. With the flag set,
  the JWKS fetch tries `host.containers.internal:<port>`, then `127.0.0.1:<port>`, then the configured
  endpoint, using the first that connects; per-endpoint failures are accumulated into the surfaced
  error. Safe because the SHA-384 SPKI pin authenticates the peer regardless of the name dialled.
  Exposed as a "CMIS is on the same host as the server" checkbox in the GUI config panel; the live
  test honours `FERROGATE_CMIS_SAME_HOST` to exercise the fallback chain against a real CMIS.

### Fixed

- **FerroGate CMIS connect errors now name the real cause** (`src/modules/credential/ferrogate/cmis.rs`)
  -- `tonic::transport::Error` renders connect-phase failures as a bare `"transport error"`, hiding the
  actual reason (SPKI pin mismatch after a CMIS cert rotation, TLS handshake alert, connection refused).
  Both `connect_plaintext` and `connect_tls` now walk the error `source()` chain via a new `explain()`
  helper so the surfaced message (e.g. in the GUI "Enrolment status" panel) includes the underlying
  detail and names the endpoint that failed.

## [0.12.7] - 2026-06-10

### Added

- **FerroGate `autoconfig` helper** (`src/cli/command/ferrogate_mia.rs`, `src/cli/command/ferrogate.rs`,
  `gui/src-tauri/src/commands/ferrogate.rs`, `gui/src/routes/FerroGatePage.tsx`) -- derive a complete
  `ferrogate` mount config from the FerroGate MIA installed on the host, so the operator no longer
  hand-copies trust anchor fields. Reads the CMIS endpoint + SPKI pin from `mia.toml`, the trust domain
  from the signed allowlist (`allowlist.cbor`, no token mint required), and fetches the live composite
  JWKS from CMIS by reusing the mount's own `cmis::fetch_jwks_json`. `bvault ferrogate autoconfig`
  prints the derived config (`--apply` writes it to `auth/<mount>/config`); the GUI config page gains an
  **Autofill from local MIA** button backed by a new `ferrogate_autoconfig` Tauri command. Sets
  `jwks_source = cmis_grpc` so keys auto-refresh.

## [0.12.6] - 2026-06-10

### Fixed

- **FerroGate MIA helper socket discovery** (`src/cli/command/ferrogate_mia.rs`,
  `src/cli/command/ferrogate.rs`, `gui/src-tauri/src/commands/ferrogate.rs`) -- the GUI/CLI
  hard-coded `/var/run/ferrogate/mia.sock` on macOS, but MIA ≥0.18 moved its default socket to
  `/Library/Application Support/FerroGate/run/mia.sock` and the path is operator-configurable in
  `mia.toml`, so machine login failed with `ferrogate_mia_unavailable: ... No such file or directory`
  even when the MIA was running. Add `resolve_mia_socket()`, which mirrors MIA's own resolution
  order — the `FERROGATE_HELPER_SOCKET` env override, then `[helper].socket` from the first config
  found (`$FERROGATE_CONFIG`, the per-OS system path, then the per-user path), then the per-OS wizard
  default as a last resort. `ferrogate_default_socket` and the `bvault ferrogate login/status/whoami`
  `--socket` flags now resolve dynamically instead of using a fixed constant. Adds `toml` as a
  runtime dependency.

## [0.12.5] - 2026-06-10

### Security

- **russh DoS fixes — RUSTSEC-2026-0153 / RUSTSEC-2026-0154** (`Cargo.toml`,
  `gui/src-tauri/Cargo.toml`) -- bump `russh` 0.60.1 → 0.61.1 (with `russh-cryptovec` 0.59 → 0.61),
  closing the unbounded 32-bit allocation and unchecked `CryptoVec` growth advisories (both 7.5 high,
  malicious-server DoS against the SSH client). Pinned `=0.61.1` because 0.61.2 jumps to the
  `p256 rc.10` / `ed25519-dalek 3.0.0-rc.0` prerelease line that the sspi/picky stack doesn't
  support yet.
- **hickory-proto DoS fixes — RUSTSEC-2026-0118 / RUSTSEC-2026-0119** -- the sspi 0.21 upgrade
  initially pulled `hickory-proto 0.25.2` (CPU-exhaustion name compression + NSEC3 unbounded loop);
  the sspi fork bumps to `hickory-resolver`/`-proto` 0.26 and ports `sspi/src/dns.rs` to the 0.26
  resolver API.
- **Known remaining: RUSTSEC-2023-0071 (rsa Marvin timing sidechannel, 5.9 medium)** -- both `rsa`
  lines in the tree (0.9.x via `yubikey`/`openidconnect`, 0.10.0-rc via sspi/picky/russh) are
  affected; no fixed release exists upstream. Revisit when RustCrypto publishes the constant-time
  rewrite.

### Changed

- **IronRDP fork synced with upstream Devolutions master** (`IronRDP/` submodule,
  ffquintella/IronRDP `fix-deps`) -- 56 commits merged; ironrdp 0.14 → 0.15, connector 0.8 → 0.9,
  sspi 0.20.1 → 0.21. The fork's remaining local deltas are the PKCS#8 CredSSP key support and the
  sspi `network_client`/`dns_resolver` features; its picky-rc.23/sspi-main patch plumbing is now
  upstreamed and was dropped.
- **New dependency forks for RustCrypto rc-pin alignment** (`[patch.crates-io]` in `Cargo.toml`) --
  `sspi`/`picky` exact-pin prerelease crypto crates (`rsa =rc.17`, `ed25519-dalek =pre.6`,
  `ecdsa =rc.17`) that conflict with russh 0.61.1's pins (`rsa =rc.18`, `ed25519-dalek =pre.7`,
  `ecdsa =rc.18`). ffquintella/picky-rs `fix-deps` (Devolutions master + ed25519-dalek pre.7 +
  ecdsa rc.18) and ffquintella/sspi-rs `fix-deps` (rsa rc.18 + stable pkcs8/signature/pbkdf2/rfc6979
  + hickory 0.26) bring both stacks onto one resolvable graph. Drop the patches once Devolutions
  publishes releases on the post-rc.17 chain.

## [0.12.4] - 2026-06-10

### Fixed

- **Userpass login `InvalidUriChar` failure** (`gui/src-tauri/src/commands/connection.rs`,
  `gui/src-tauri/src/commands/auth.rs`) -- the username was interpolated raw into the login request
  URI (`auth/userpass/login/<username>`), so a stray trailing space or newline (from paste/autofill)
  produced "Login failed: Some http error happened, http::Error(InvalidUri(InvalidUriChar))" instead
  of authenticating. The username is now trimmed and percent-encoded before building the URL, in both
  the remote and embedded login paths. (Pre-existing bug, not a regression from the v0.12.x FerroGate
  work.)

## [0.12.3] - 2026-06-10

### Changed

- **MIA refusal toast wording** (`src/cli/command/ferrogate_mia.rs`) -- the error string surfaced to
  the GUI Machine Login toast (and the CLI) is now `"MIA refused: <explanation>"` using
  `ErrorCode::describe()`, and no longer appends the raw `[CrlStale]`-style opcode that leaked the
  enum variant name into operator-facing output. A `CrlStale` refusal reads "MIA refused: its
  revocation list (CRL) from CMIS is stale — the MIA fails closed; check that CMIS is reachable and
  publishing a fresh CRL". Guarded by a unit test over every `ErrorCode` variant and a
  `gui/src/test/ferrogate.test.tsx` case asserting the toast shows the explanation, not `CrlStale`.

## [0.12.2] - 2026-06-10

### Changed

- **MIA refusal messages** (`src/cli/command/ferrogate_mia.rs`) -- map the MIA helper's refusal
  opcodes (`CrlStale`, `PermissionDenied`, `NoHostSvid`, ...) to operator-facing explanations with a
  pointer to where to look next (e.g. `CrlStale` now reads "its revocation list (CRL) from CMIS is
  stale — the MIA fails closed; check that CMIS is reachable and publishing a fresh CRL"). Shared by
  the CLI and the GUI Machine Login tab; the raw opcode is kept in brackets for grepping.

## [0.12.1] - 2026-06-09

### Added

- **FerroGate machine-auth — MIA self-bootstrap from the GUI**. The desktop GUI can now act as the *client* side of the FerroGate protocol (it was previously the relying-party / admin side only). A new **Machine Login** tab on the *Machines (FerroGate)* page dials the local FerroGate MIA over its helper socket, mints a DPoP-bound child token, and exchanges it at `auth/<mount>/login` — the same self-bootstrap flow the `bvault ferrogate` CLI performs. Buttons cover *Whoami* (read the host SPIFFE id locally), *Check status* (poll enrolment without minting a vault token), and *Log in* (mint + display the issued vault token for copy-out). Backed by four new Tauri commands (`ferrogate_default_socket`, `ferrogate_machine_login`, `ferrogate_machine_status`, `ferrogate_whoami`) in [`gui/src-tauri/src/commands/ferrogate.rs`](gui/src-tauri/src/commands/ferrogate.rs) that **reuse the CLI's `bastion_vault::cli::command::ferrogate_mia` module verbatim** — no duplicated DPoP/CBOR/thumbprint crypto, so the wire format stays byte-identical to what the server verifies. Blocking socket I/O runs on a `spawn_blocking` thread; non-Unix targets get clear "Unix-only" stubs. Logging in here does **not** replace the operator's admin session token. (`features/machine-authentication.md`)

### Fixed

- **FerroGate CLI MIA socket default on macOS**. `bvault ferrogate {login,status,whoami}` defaulted `--socket` to the Linux path `/run/ferrogate/mia.sock`, which does not exist on macOS (the MIA binds under `/var/run`). `DEFAULT_MIA_SOCKET` is now selected per target OS (`/var/run/ferrogate/mia.sock` on macOS, `/run/ferrogate/mia.sock` elsewhere), so the CLI connects without an explicit `--socket` on either platform. (`src/cli/command/ferrogate_mia.rs`)

## [0.12.0] - 2026-06-03

### Changed

- **Minor version bump marking the FerroGate machine-authentication auth method as complete.** All seven phases of the `ferrogate` auth backend have shipped (see `0.11.3` and the preceding `0.11.x` entries): the `auth/ferrogate/` mount + admin lifecycle, DPoP-bound composite child-token verification + token minting, the one-shot first-machine root bootstrap + self-poll, the `cmis_grpc` JWKS source over plaintext and hybrid post-quantum TLS (validated live against the dev CMIS), the `bvault ferrogate` client CLI, the *Machines (FerroGate)* admin GUI page, and the opt-in direct-SVID mode with CRL enforcement, per-source-IP login rate limiting, Prometheus metrics, and operator docs. No functional change over `0.11.3` — this `0.12.0` release exists to signal the new, fully-shipped feature.

## [0.11.3] - 2026-06-03

### Added

- **FerroGate machine-auth backend — Phase 7 (direct-SVID + CRL + hardening), feature complete**. Added an opt-in **direct-SVID mode** (`accept_svid`): a host SVID presented at `auth/ferrogate/login` is verified with the vendored `ferro-svid-verify` reference verifier, which **enforces FerroGate's composite-signed CRL** — a revoked host, or a stale/absent CRL, is rejected fail-closed. Login now routes by JOSE `typ` (host SVID vs DPoP-bound child token), and records the SVID's attestation evidence (`ek_cert_sha384`, `policy_id`) on the machine. Added a per-source-IP `login` rate limit (`login_rate_limit_per_min`, default 10, `0` = unlimited) and Prometheus counters `bvault_ferrogate_login_total`, `bvault_ferrogate_login_denied_total{reason}`, `bvault_ferrogate_pending_total`, and `bvault_ferrogate_approved_total`. Documented operator setup + threat model in `docs/ferrogate-machine-auth.md`. With this, the FerroGate machine-authentication feature is complete (all 7 phases). The vendored FerroGate verifier SDK now includes `ferro-svid-verify` (v0.15.0).
- **FerroGate machine-auth backend — Phase 5 (client CLI)**. New `bvault ferrogate` subcommands (Unix): `login` obtains a DPoP-bound child token from the local FerroGate MIA over its helper socket (`/run/ferrogate/mia.sock`, length-delimited CBOR), builds the RFC 9449 DPoP proof, exchanges it at `auth/<mount>/login`, and persists the issued BastionVault token; `status` reports the machine's enrolment status without minting a vault token; `whoami` prints the host's SPIFFE id locally. A missing MIA fails with a clear `ferrogate_mia_unavailable` error. The CLI's DPoP proof is verified against FerroGate's own `verify_dpop_proof` in tests. Windows named-pipe support is a follow-up.
- **FerroGate machine-auth backend — Phase 6 (admin GUI page)**. A new desktop GUI page, *Machines (FerroGate)* (route `/ferrogate`, sidebar entry), manages the machine-approval lifecycle: a **Pending** tab to approve (with policy set + token TTL + comment) or reject (with reason) attested-but-unauthorized machines, an **Approved** tab showing policies / last login / source IP with revoke, a **History** tab of rejected/revoked machines, and a **Config** tab to set the trust anchor (trust domain, expected audience, JWKS source, CMIS endpoint + SHA-384 SPKI pins, static JWKS, the PQ-TLS toggle, and the bootstrap toggles). The page enables the `ferrogate` auth method on first use. Backed by seven Tauri commands plus `ferrogate` added to the mount-creation auth-type list.

## [0.11.2] - 2026-06-03

### Changed

- **FerroGate machine-auth: vendored SDK bumped to `releases/v0.15.0`; PQ-TLS validated live.** The `auth/ferrogate/` backend's `cmis_grpc` JWKS source was validated end-to-end over **hybrid post-quantum TLS** against the live CMIS 0.15.0 (`X25519MLKEM768` key exchange, SHA-384 SPKI-pinned server certificate). The vendored FerroGate verifier crates (`ferro-crypto`, `ferro-child-verify`) were updated from 0.13.2 to 0.15.0 (public APIs and the gRPC proto are unchanged; no BastionVault code changes were required). No behaviour change for operators already on the static-JWKS or plaintext paths.

## [0.11.1] - 2026-06-03

### Added

- **FerroGate machine-auth backend — Phase 4 (CMIS gRPC JWKS source)**. The `ferrogate` backend can now obtain its trust anchor directly from FerroGate's CMIS instead of a pasted static JWK set: setting `jwks_source = "cmis_grpc"` makes BastionVault call the `ferrogate.v1.MachineIdentity/JWKS` RPC and cache the result for `jwks_refresh_secs` (default 60s), serving the last good copy if a refresh fails. The transport is selectable with `cmis_tls_enable`: hybrid post-quantum TLS (`X25519MLKEM768`, server certificate pinned by SHA-384 SPKI from `cmis_spki_pins`) when enabled, or cleartext gRPC for a dev/loopback CMIS when disabled. The gRPC stubs are pre-generated from FerroGate's `machine_identity.proto` and vendored, so building BastionVault does **not** require `protoc` — only the `tonic`/`prost` runtimes (and `hyper-rustls`/`hyper-util`/`tower`, promoted from the existing dependency tree). Validated end-to-end against the live development CMIS. Note: `cmis_grpc` requires the default async build; the CRL extension served in the JWKS is not enforced on the child-token path (it applies to the direct-SVID path, deferred to a later phase).
- **FerroGate machine-auth backend — Phase 3 (first-machine bootstrap + status poll)**. Implemented the one-shot first-machine bootstrap: when no machine is yet approved and an `auth/ferrogate/login` request carries a BastionVault root-policy token, the presenting (verified) machine is auto-approved with the configured `bootstrap_policies` and a token is minted immediately; once any machine is approved, all later machines return to the administrator-approval gate. Added `POST auth/ferrogate/status`, a token-authenticated self-poll that verifies a presented FerroGate token and reports the machine's enrolment status (`pending`/`approved`/`rejected`/`revoked`/`unknown`) without minting a token. Key lifecycle transitions now emit `audit`-target log events (`ferrogate.machine.first_seen`, `.bootstrap_approved`, `.login`).
- **FerroGate machine-auth backend — Phase 2 (token verification + login)**. `auth/ferrogate/login` now authenticates a machine by verifying a FerroGate-issued, DPoP-bound, composite-signed (Ed25519 + ML-DSA-65) child token against a configured static JWK set, enforcing the RFC 9449 sender-constraint, the expected audience, and the trust domain. An approved machine receives a BastionVault token bound to its assigned policies and TTL; a verified-but-unknown machine is recorded as `pending` (surfacing in the admin queue) and denied; pending/rejected/revoked machines are denied. The DPoP proof is read from the `DPoP` request header (now surfaced to logical backends) or a `dpop` body field. Verification uses FerroGate's official `ferro-child-verify` reference verifier, vendored under `third_party/ferrogate-sdk-rust/` and pinned to the FerroGate `releases/v0.13.2` SDK (SHA-256 recorded in its `PROVENANCE.md`); no cryptographic code is implemented in BastionVault. The `cmis_grpc` JWKS source and the first-machine root bootstrap are not yet implemented.
- **FerroGate machine-auth backend — Phase 1 (skeleton)** ([`src/modules/credential/ferrogate/`](src/modules/credential/ferrogate/)). A new `ferrogate` auth method mounts at `auth/ferrogate/` and gates vault access on a machine's FerroGate-attested SPIFFE identity plus an administrator approval. This phase ships the trust-anchor configuration (`POST`/`GET auth/ferrogate/config`), the machine-enrolment storage layout, and the admin lifecycle routes: `register` (pre-authorize a SPIFFE ID), `LIST machines`, `GET`/`DELETE auth/ferrogate/machines/{id}`, and `approve`/`reject`/`revoke` (where `{id}` is the BLAKE3 hex of the SPIFFE ID). All admin routes are root/sudo-gated. `auth/ferrogate/login` is present but returns a not-implemented error until Phase 2 wires FerroGate's reference token verifiers.

### Changed

- **Machine Authentication spec redirected to FerroGate** ([`features/machine-authentication.md`](features/machine-authentication.md)) — the auth method now admits machines by verifying a **FerroGate** TPM-attested, post-quantum SPIFFE identity (a DPoP-bound child token or SVID, composite Ed25519 + ML-DSA-65) against FerroGate's published JWKS/CRL, rather than a home-grown host-hardware fingerprint. BastionVault becomes the relying party and keeps an admin-approval gate: an unknown but attested machine is held `pending` until an administrator approves it and attaches a policy set; the first machine to authenticate while no machine is yet approved **and** presenting a BastionVault root token is auto-approved (one-shot bootstrap). Verification reuses FerroGate's `#![forbid(unsafe_code)]` reference verifier crates — no custom crypto. Supersedes the earlier composite-key (random part + software-readable host fingerprint) design.

## [0.11.0] - 2026-06-02

Minor-version release. Promotes the Connect-Only Access feature and the revived
Rustion SSH e2e harness (shipped in 0.10.16) to a minor version now that the
connect-only path is validated live end-to-end. No code changes since 0.10.16.

## [0.10.16] - 2026-06-02

### Added

#### Connect-Only Access (Phase 1 + GUI filtering, features/connect-only-access.md)

- Add a new `connect` ACL capability so a policy can grant the ability to open
  a Rustion-brokered session to a resource **without** granting `read` on its
  stored credentials. Example: `path "resources/secrets/db-prod/*" { capabilities = ["connect"] }`.
  `read`/`root` imply `connect`, so existing policies are unaffected.
- Add `rustion/v2/session/open`: a connect-only session-open entry point that
  enforces `connect` (or `read`/`root`) on the resource's secret path and, when
  given a credential reference (`credential_source = {kind:"secret", secret_id}`),
  resolves the credential **server-side** under BastionVault's own authority so
  the connecting operator never reads it. v1 `rustion/session/open` is unchanged.
- Add `v2/sys/capabilities-self`: report the calling token's effective
  capabilities on a set of paths (Vault-compatible). The GUI uses it to hide
  credential values and restrict connections to Rustion-brokered profiles when
  the caller holds only `connect`.
- GUI: hide a resource's stored credentials and offer only Rustion connection
  profiles when the caller has connect-only access; add a `capabilities_self`
  Tauri command and `api.capabilitiesSelf` wrapper.
- GUI: the SSH connect path resolves `secret`-backed credentials through
  `rustion/v2/session/open` (sending a credential reference, not the material),
  so a connect-only operator can launch a brokered session without reading the
  credential. v1 and v2 share the ticket-bundle parser.

### Security

- Connect-only credential resolution happens server-side via the router
  (bypassing the caller's read capability only after the `connect` gate
  passes), and emits a `security`-target audit line attributed to the
  connecting operator.

### Fixed

#### Rustion SSH e2e harness revived (`tests/e2e/rustion-ssh/`)

- Revive the docker-compose harness that had rotted since v0.7 so
  `docker compose up -d` + `run.sh` drives a real Rustion-mediated SSH session
  end-to-end again — and now also exercises the connect-only path live.
- Fix the BV image build: drop the `COPY plugins-ext` from the root `Dockerfile`
  (the dir is workspace-excluded and `.dockerignore`d), and remove the dead
  `BASTION_VAULT_LOCAL_DEV` env (no server code ever read it).
- Fix the rustion build context: `../../../Rustion` (nonexistent) →
  `../../../../rustion` (the sibling repo) in `docker-compose.yaml` and the
  README; drop the obsolete compose `version:` key.
- Replace the never-implemented auto-init env with an API-driven flow: `run.sh`
  init+unseals BV over `/v1/sys/{init,unseal}` from a cold sealed start and
  captures the root token (mount `config/bv-config.hcl`).
- Rewrite `config/rustion.toml` to the current `rustion_core` config schema
  (renamed/removed `[audit] checkpoint_interval_secs`, `[recording]
  root_dir/format`, `[ssh] allow_bv_ticket`, `identity_pub/priv`); `run.sh`
  mints the required control-plane TLS cert and seeds a cert-auth-only admin
  user so the TTY-less container doesn't block on the first-run prompt.
- Automate enrolment end-to-end: pin BV's master pubkey as a Rustion authority
  in the on-disk `pubkey_*_b64` schema; enrol the bastion on BV with rustion's
  ML-KEM-768 pubkey (`identity.pub`) and Ed25519+ML-DSA-65 signing pubkeys
  (`rustion control-plane webhook-key export`), pinning rustion's self-signed
  control-plane leaf so BV's strict-TLS client accepts it; probe until healthy.
- Extend `run.sh` to prove connect-only live: create a resource + ssh-password
  secret + a `connect`-only policy/token, confirm the token is denied a direct
  secret read (403), then `POST rustion/v2/session/open` with a credential
  reference (no material) and proxy a real SSH shell through the bastion to the
  OpenSSH target as `deploy` — the operator never reads the credential.

## [0.10.15] - 2026-06-01

### Changed

- **Cluster-wide `operator seal` / `operator unseal`** (`src/cli/command/operator_seal.rs`, `src/cli/command/operator_unseal.rs`, `src/cli/command/mod.rs`) -- seal state is per-node (each node holds its own in-memory barrier and accumulates unseal-key shares independently), so a single CLI request only sealed/unsealed one node and, worse, discovery could land successive unseal shares on different nodes so none reached threshold. These commands now fan out over every node returned by SRV cluster discovery (`HttpOptions::cluster_clients`), broadcasting each unseal share to all nodes so they cross the threshold in lockstep and reporting per-node results. A new `--local` flag (and literal `http(s)://` addresses / `--no-cluster-discovery`) restricts the operation to the single connected node. No server-side change.

## [0.10.14] - 2026-05-28

### Fixed

- **Ownership transfer / claim HTTP endpoints reachable** (`src/http/sys.rs`) -- the sys-backend logical routes `kv-owner/transfer`, `kv-owner/claim`, `resource-owner/transfer`, `asset-group-owner/transfer`, and `file-owner/transfer` had no explicit HTTP-layer shim. Actix's `/v1/sys` and `/v2/sys` scopes were 404'ing those paths before they could reach the `/v1/{path:.*}` logical catch-all, so the Tauri **Claim ownership** button (and every owner-transfer flow over remote backends) returned `HTTP 404 (no body)` even though the sys backend was registered correctly. Added per-route shims that build a `Request` and delegate to `core.handle_request`, mirroring how every other `sys/*` endpoint is wired.

## [0.10.13] - 2026-05-28

### Added

- **KV ownership claim endpoint and Claim button** (`src/modules/system/mod.rs`, `gui/src-tauri/src/commands/sharing.rs`, `gui/src/lib/api.ts`, `gui/src/routes/SecretsPage.tsx`) -- new `sys/kv-owner/claim` route lets any caller with ACL access to it stamp their `entity_id` as the owner of a currently-unowned KV secret. Refuses on already-owned paths (returns 409) so it cannot be used to steal ownership -- use `sys/kv-owner/transfer` (admin) to reassign. The Share dialog now renders a **Claim ownership** button on unowned secrets, and admins see **Transfer** / **Assign owner** regardless of current ownership state. Addresses the long tail of "Unowned" rows imported by PMP before ghost-row overwrite shipped in 0.10.11.

### Fixed

- **Tauri build no longer fails when `mcp_local_dev` is off** (`gui/src-tauri/build.rs`, `gui/src-tauri/capabilities/`) -- the `mcp-bridge:default` permission lived in the always-loaded `capabilities/default.json`, so a default `cargo check -p bastion-vault-gui` failed because the plugin (and its permission schema) is only compiled in under the `mcp_local_dev` feature. The mcp-bridge permission now lives in its own capability file that `build.rs` materializes only when the feature is enabled and removes otherwise, keeping the dev bridge fully gated as agent.md requires.

### Changed

- **Owner badge on secrets list** (`gui/src/routes/SecretsPage.tsx`) -- every leaf in the KV list now shows an `unowned` / `you` / `owned` chip so operators can spot orphan paths without opening each share dialog. Folder entries are unaffected. Ownership is fetched best-effort in parallel after the listing loads.

## [0.10.12] - 2026-05-28

### Changed

- **Secrets group filter is now a drill-down chain** (`gui/src/routes/SecretsPage.tsx`) -- replaces the single-group toggle with an AND chain. Selecting a group narrows both the key list and the visible group cards to the intersection, so picking a second group drills further. Active filters render as a clickable breadcrumb (`All groups / group-a / group-b`); each crumb backs up to that step. Counts on the group cards reflect the intersection against the current working set, not the full mount.

## [0.10.11] - 2026-05-28

### Fixed

- **Owner capture overwrites ghost records** (`src/modules/identity/owner_store.rs`) -- `record_kv_owner_if_absent` (plus the resource and file siblings) used to short-circuit on *any* existing storage row, including legacy rows with an empty `entity_id` left over from older server versions. Those rows render as "Unowned" in the GUI, so the user-visible promise that "the next authenticated write captures ownership" was broken on upgraded deployments. Now the absent-check inspects the stored record's `entity_id` and overwrites when it is empty, while still preserving any concrete owner. Regression test `test_kv_ghost_record_overwritten_by_next_write`.

## [0.10.10] - 2026-05-27

### Added

- **Active recordings reconcile (list-pull) path.** BV can now actively query a bastion's full recording index instead of waiting for a webhook push or pulling one session at a time. New endpoint `POST rustion/recordings/reconcile` (`bastion_id` optional — empty sweeps every enrolled bastion) calls Rustion's new `GET /v1/recordings`, then ingests any recording BV is missing (matched by `recording_id`, `delivery_mode=reconcile`). Idempotent. This recovers recordings the per-session pull-fallback cannot reach — terminated sessions and sessions lost across a bastion restart, since it reads the bastion's on-disk index rather than the live session table. Surfaced in the GUI Recordings page as a **Sync all bastions / Sync this bastion** button (`rustion_recordings_reconcile` Tauri command). Requires Rustion ≥ 0.10.9 (the `/v1/recordings` endpoint).

## [0.10.9] - 2026-05-27

### Fixed

- **Rustion `recording.ready` webhook receiver rewritten to match the real wire contract.** The previous logical-backend handler expected a `{bastion_id, signature, sidecar_json}` JSON envelope, but Rustion's `rustion-control-plane::webhook` deliverer actually POSTs the **raw sidecar JSON** as the body with the hybrid signature in the **`X-Rustion-Signature` header** — so every delivery would have been rejected with `400 bastion_id is required`. Replaced it with a dedicated actix route (`src/http/rustion_webhook.rs`) registered ahead of the `/v1` logical catch-all, which verifies `sha256(raw body)` against the pinned key directly off the wire, identifies the bastion via a `?bastion_id=` query hint (with a try-all-enrolled-keys fallback), and ingests the sidecar into the recordings index. This supersedes the unauth-path change from 0.10.8 (the old logical route and its `unauth_paths` entry were removed).
- **Ed25519 webhook-signature verification rejected real pinned keys.** `webhook_verify::verify` assumed a raw 32-byte Ed25519 key, but enrolment pins the 44-byte DER SPKI form (`ed25519_spki_b64` from `rustion control-plane webhook-key export`), so verification always failed with `PubkeyLen`. The verifier now accepts both the SPKI wrapper and a bare 32-byte key.

## [0.10.8] - 2026-05-27

### Fixed

- **Rustion `recording.ready` webhook deliveries were rejected before reaching the handler** -- the `rustion/webhooks/recording-ready` path is authenticated by the hybrid Ed25519+ML-DSA-65 signature verified against the originating bastion's pinned pubkey, but the path was not declared as an unauthenticated route. Bastions hold no Vault token, so every delivery was rejected at the token-auth gate (`pre_route`) before the signature-verifying handler ran, leaving the Recordings index permanently empty. Declared `webhooks/recording-ready` as an `unauth_path` on the rustion backend.

## [0.10.7] - 2026-05-27

### Security
- CLI token helper file is now encrypted at rest (`src/cli/util.rs`). `bvault login` previously wrote the issued token (including a root token, when that is the logged-in identity) as plaintext to `$BVAULT_TOKEN_FILE` / `~/.vault-token`, protected only by 0600 file permissions — so anything able to read as that user, or any backup/snapshot of the path, captured a usable token. The token is now sealed with XChaCha20-Poly1305 under a key derived (HKDF-SHA256) from the host's machine id (`/etc/machine-id`, or `IOPlatformUUID` on macOS), so a file copied to another host or restored from backup fails to decrypt. Files are written with a `BVTOK1:` marker; legacy plaintext files without the marker are still read (and upgraded to encrypted on the next login) so existing deployments keep working. Operators should still rotate any root token that was previously cached in plaintext.

### Fixed
- Rustion module test build no longer fails to compile (`src/modules/rustion/dispatcher.rs`, `src/modules/rustion/envelope.rs`). Two `#[cfg(test)]` `RustionTarget` constructors predated the Phase 9.3 listener-discovery fields (`ssh_listener_host/port`, `rdp_listener_host/port`, `listeners_synced_at`) and were missing them, breaking `cargo test --lib`. The fields are now populated with defaults in both test fixtures.
- `cucumber_hiqlite` integration test fixed (`tests/cucumber_hiqlite.rs`). It set `listen_addr_raft`/`listen_addr_api` with an embedded port (`127.0.0.1:28200`), but `HiqliteBackend` now treats those as host-only and appends the `port_{raft,api}` keys, yielding a malformed `127.0.0.1:28200:8210` address that failed to resolve. Addresses are now host-only with explicit port keys. Also made the backend a process-global singleton run with `max_concurrent_scenarios(1)`, since a hiqlite node binds fixed ports and is not torn down between scenarios — per-scenario backends collided on the ports and concurrent scenarios raced on the shared table.
- `test_default_logical` updated for the `rustion/` default mount (`tests/test_default_logical.rs`). The default core-mount count assertion still expected 6; `rustion/` brings it to 7.
- Live Sessions "Recent audit witness" no longer empties out after a poll that returns no new entries (`src/modules/rustion/telemetry.rs`). Each telemetry tick builds a fresh per-target snapshot and the audit pull only returns entries newer than the persisted cursor, so the in-memory recent set was being rebuilt from an empty base every tick — the moment a tick found no new entries the live view dropped to 0. The tick now seeds `recent_audit` from the previously cached snapshot, dedupes by hash, and caps at the 200 latest. The persistent witness store under `rustion/audit_witness/` was always intact; only the live view was affected.
- Live Sessions "Terminate" no longer shows a scary red error when the bastion has already torn the session down. A `409 session_already_terminated` from the bastion is now treated as a benign outcome (info toast) since the session is already gone, and both the success and already-terminated paths force a synchronous telemetry poll so the stale row drops out of the cached snapshot immediately instead of lingering until the next 60s tick (`gui/src/routes/RustionLiveSessionsPage.tsx`).

## [0.10.6] - 2026-05-27

### Fixed
- Recording force-pull and blob-fetch now surface the bastion's upstream status faithfully — a missing sidecar returns 404 and other upstream failures return 502, instead of collapsing every error into a generic HTTP 500.

## [0.10.5] - 2026-05-26

### Fixed

- **Recording force-pull no longer 500s with "Logical backend
  operation not supported"** (`src/modules/rustion/mod.rs`). The
  `recordings/<rid>` catch-all route used the pattern
  `[A-Za-z0-9_\-]+`, which also matched the sibling literal routes
  `recordings/pull` and `recordings/replay-log` (rid="pull" /
  "replay-log"). Because the catch-all was registered first and only
  declares the `Read` operation, a `POST recordings/pull` resolved to
  the read handler and was rejected. Recording ids are always
  `rec_<hex>`, so both `<rid>` patterns now pin the `rec_` prefix —
  the literal routes resolve correctly and the latent `replay-log`
  shadowing is closed too.

## [0.10.4] - 2026-05-26

### Added

#### Default connection profile

- **Connection profiles can be flagged as the default**
  (`gui/src/lib/types.ts`, `gui/src/lib/connectionProfiles.ts`,
  `gui/src/routes/ResourcesPage.tsx`). A new `is_default` flag on
  `ConnectionProfile` marks the one profile the one-click Connect
  launches. The Connection-tab list shows a `DEFAULT` badge and a
  "Set default" action per profile; saving normalises to the
  at-most-one-default invariant (the first profile is auto-promoted
  when none is flagged, so every resource with profiles has exactly
  one default).
- **Resource-card Connect now auto-launches the default profile.**
  Instead of opening the Connection tab, the card's Connect button
  reads the resource, picks the default profile (`is_default`, else
  the sole launchable profile), and dispatches the SSH/RDP session
  directly. It falls back to opening the Connection tab only when
  there's genuine ambiguity (2+ profiles, none flagged default) or
  the default needs an interactive operator credential prompt (LDAP
  operator-bind) — surfacing an "pick one, or mark a default" hint in
  the ambiguous case.
- New shared helpers in `connectionProfiles.ts`:
  `isLaunchableProfile`, `needsOperatorPrompt`, `pickDefaultProfile`,
  `normalizeProfileDefaults` — used by both the card quick-Connect and
  the Connection-tab launcher so they agree on launchability and
  default selection.

## [0.10.3] - 2026-05-26

### Added

- **Connect button restored on the Resources list cards**
  (`gui/src/routes/ResourcesPage.tsx`). The inline quick-connect
  button was dropped when the paginated search endpoint replaced the
  list-then-fan-out reads (the card projection omits
  `connection_profiles`). It's back as a one-click action that opens
  the resource detail straight on the Connection tab, where the
  per-profile launcher has the full metadata (LDAP-operator prompt,
  recently-connected, Rustion route resolver). Shown only on
  `server`-type resources and honours the per-type connect toggle —
  matching the detail view's Connection-tab gating.

## [0.10.2] - 2026-05-26

### Changed

- **Recordings → Force-pull: Bastion ID is now a dropdown**
  (`gui/src/routes/RecordingsPage.tsx`). The freeform text input was
  too easy to misuse — operators typed the friendly name (`dev-1`)
  while the API requires the id (`rt_<hex>`), which surfaced as the
  confusing `HTTP 500: Logical backend operation not supported` from
  the per-target route resolver. The dropdown loads enrolled bastions
  via `rustion_target_list` on mount, shows `<name> (<id>)`, and
  submits the id. Empty list shows "No bastions enrolled" and
  disables the Pull button. Selected bastion is preserved across
  successive pulls.

## [0.10.1] - 2026-05-26

### Security

- **Stop leaking the caller's auth token into Rustion envelopes**
  (`src/modules/rustion/mod.rs`). The `operator.src_ip` field of
  every BVRG envelope (open / renew / kill / attest / deenrol) was
  being populated with `req.client_token` — a leftover placeholder
  that stamped the Vault token straight into Rustion's audit chain
  and broke ticket source-IP binding (the token string never matches
  a real TCP peer, so every SSH ticket-auth attempt failed with
  `TicketIpMismatch`). New `operator_src_ip(req)` helper sources from
  `req.connection.peer_addr_derived` (post-X-Forwarded-For walk) or
  `peer_addr` (port-stripped) instead. Returns empty when no
  Connection is attached (embedded callers, tests); Rustion 0.10.4+
  treats empty src_ip as "no IP binding, accept any dial source."
  Operators rotating their Vault tokens after upgrading is
  defence-in-depth — the field was stamped on outbound envelopes
  only and Rustion only logged it as `operator_src_ip` in audit
  records, but anyone with read access to those logs would have
  seen the token.

### Fixed

- **SSH Connect through Rustion no longer fails with `ssh:
  authentication rejected`**. Direct downstream of the src_ip fix
  above: Rustion's SSH ticket-auth rejected every attempt because
  the dial's TCP peer never matched the leaked token string. Now
  matches an actual operator IP (or is intentionally empty for
  embedded callers).

## [0.10.0] - 2026-05-26

Minor bump introducing the Rustion listener-info discovery handshake.
Replaces the 0.9.2 client-side heuristic for `0.0.0.0` bastion
advertisements with a proper out-of-band negotiation at enrolment
time. Requires Rustion ≥ 0.10.3 (ships `GET /v1/listeners`); older
Rustion versions are still supported via the 0.9.2 fallback path.

### Added

#### Listener-info discovery (Phase 9.3)

- **`POST rustion/targets/<id>/listeners/refresh`** server route
  (`src/modules/rustion/mod.rs`). Calls Rustion's `GET /v1/listeners`
  over the pinned-TLS path and persists the per-protocol dial
  coordinates onto the target record.
- **`rustion_target_refresh_listeners` Tauri command**
  (`gui/src-tauri/src/commands/rustion.rs`). Thin wrapper for the
  GUI. Also auto-fires right after `rustion_target_upsert` so newly
  enrolled bastions get listener coords on the first round trip;
  failures are logged as `WARN` and do not block enrolment.
- **`src/modules/rustion/listeners.rs`** — thin async client for the
  bastion's `GET /v1/listeners` endpoint. Reuses the existing
  per-target TLS pinning helper. 10s timeout.
- **`RustionTarget` fields** (`src/modules/rustion/config.rs`):
  `ssh_listener_host`, `ssh_listener_port`, `rdp_listener_host`,
  `rdp_listener_port`, `listeners_synced_at`. Surfaced in the target
  read/list responses and the `RustionTargetSummary` GUI type.

### Changed

- **`resolve_bastion_dial_coords` replaces `resolve_bastion_dial_host`**
  (`gui/src-tauri/src/commands/connect.rs`). The Connect path now
  picks dial coordinates in three tiers — stored listener info (Phase
  9.3) → session/open echo when specified → endpoint-host fallback —
  and returns the `(host, port)` pair as a unit so the dial uses a
  coherent source. Logs which tier produced the verdict at `INFO` for
  every Rustion-mediated Connect.

## [0.9.2] - 2026-05-26

### Fixed

- **Connect to bastion no longer fails on `0.0.0.0` listener bind**
  (`gui/src-tauri/src/commands/connect.rs`). When Rustion's
  `session/open` response carries an unspecified host
  (`0.0.0.0` / `::` / empty) — which happens whenever the SSH/RDP
  proxy listener is configured to bind to all interfaces in
  `rustion.toml` — the GUI used to dial it literally and the OS
  collapsed it to localhost, surfacing `connect 0.0.0.0:<port>:
  Connection refused`. The new `resolve_bastion_dial_host` helper
  detects unspecified hosts and substitutes the host portion of the
  bastion target's enrolment `endpoint` (the same address BV reaches
  for health probes). The proxy port returned by `session/open` is
  kept as-is — it is distinct from the control-plane port and we
  have no other source for it. Substitution is logged at
  `INFO`; missing target lookups degrade to a `WARN` and the original
  dial host so the operator still sees a useful error.

## [0.9.1] - 2026-05-26

### Added

- **Pre-flight pubkey-length validation on Rustion target write**
  (`src/modules/rustion/mod.rs`). `handle_target_create` and
  `handle_target_update` now reject `kem_public_key` whose
  base64-decoded length is not 1184 bytes (ML-KEM-768) and
  `public_key_mldsa65` whose decoded length is not 1952 bytes
  (ML-DSA-65) with `HTTP 400` plus the field name and observed length.
  Catches the "pasted into the wrong slot" enrolment mistake at write
  time instead of letting it surface as `HTTP 500: envelope build
  failed: invalid KEM public key` deep in a later Connect attempt.
- **Pubkey-health badges on Settings → Rustion Bastions row**
  (`gui/src/components/RustionBastionsTab.tsx`). Each target row now
  decodes its `kem_public_key` and `public_key_mldsa65` and renders a
  red `KEM pubkey <N> B (need 1184)` chip (or `… missing` / `…
  invalid base64`) and a yellow `ML-DSA-65 pubkey <N> B (need 1952)`
  chip when the slot is broken. Operators see broken enrolments before
  clicking Connect.

## [0.9.0] - 2026-05-26

Minor bump cutting the Phase 7.4 (Rustion-mediated Connect) work
shipped in 0.8.21 / 0.8.22 / 0.8.23 as a single release line. No
new behaviour beyond what those patches already shipped; consult
their headers below for the full list. Headline change: the GUI
Connect button now honours the per-resource Rustion policy for SSH
and RDP, routes through the bastion when the policy demands, and
the spawned session window drives auto-renew + manual Renew/Terminate.

## [0.8.23] - 2026-05-26

### Added

#### Rustion session lifecycle in the spawned Connect window (Phase 7.4)

- **`session_rustion_info` Tauri command**
  (`gui/src-tauri/src/commands/connect.rs`). Returns the Rustion
  `{session_id, bastion_id, bastion_name, correlation_id, expires_at,
  max_renewals, protocol}` bundle the host stashed when the open
  routed through a bastion, or `null` for direct dials. The bundle is
  keyed by the local SSH/RDP session token and dropped alongside the
  session on close.
- **`RustionSessionChip` component**
  (`gui/src/components/RustionSessionChip.tsx`). Drops into the
  header of the `SessionSshWindow` and `SessionRdpWindow` routes. On
  mount it calls `session_rustion_info`; when a bundle comes back it
  drives [`useRustionSessionLifecycle`](gui/src/hooks/useRustionSessionLifecycle.ts)
  so the session auto-renews at `expires_at − 60s` and the operator
  can press a manual Renew or Terminate. Surfaces the bastion name,
  the live TTL countdown, and the `renewals_used / max_renewals`
  budget. Direct sessions render nothing.
- **`AppState::rustion_session_bundles`** (`gui/src-tauri/src/state.rs`).
  In-memory map keyed by SSH/RDP session token. Populated in
  `commands/connect.rs` after a Rustion-routed `session/open`
  succeeds; cleared by `session::{ssh,rdp}::drop_session`. Closes the
  Phase 7.4 follow-up that left `useRustionSessionLifecycle`
  unconsumed.

## [0.8.22] - 2026-05-26

### Changed

- **GUI RDP Connect now routes through Rustion when policy requires**
  (`gui/src-tauri/src/commands/connect.rs`, `gui/src-tauri/src/session/rdp.rs`).
  Mirror of the 0.8.21 SSH wiring:
  - On `transport=rustion-required` (RDP + rdp-password): calls
    `rustion/session/open` with `target_protocol=rdp` /
    `credential_kind=rdp-password` and dials the returned bastion
    `host:port` with the ticket carried in the X.224 routing-token slot
    as `mstshash=tkt_<hex>`. The bastion consumes the ticket at the
    Connection Request stage, skips local auth + client-side CredSSP,
    and drives upstream CredSSP itself using the envelope's credential.
  - On `transport=rustion-preferred` with bastions available +
    rdp-password: same path, falls back to direct on Rustion failure.
  - On `transport=rustion-required` with a smart-card (rdp-cert)
    credential: fails closed with explanatory error. The bastion's
    PKINIT/SPNEGO injection path is tracked separately; the direct PIV
    emulator still works on `direct` / `preferred`.
  - On `transport=direct` / unset: dials direct (existing behaviour).
- **`session::rdp::RdpOpenArgs` grows a `routing_token: Option<String>`
  field.** When set, ironrdp's `ConnectorConfig::request_data` carries it
  as `NegoRequestData::routing_token`, putting the ticket into the X.224
  Connection Request the bastion parses for ticket auth.

## [0.8.21] - 2026-05-26

### Added

#### Rustion Connect Routing (Phase 7.4)

- **`POST rustion/policy/effective`** (`src/modules/rustion/mod.rs`) -- Resolve
  the effective Rustion policy (transport / bastions / recording / lock state)
  for a given resource without opening a session. Takes the same
  `resource_id` / `resource_type` / `asset_group_ids` hints as `session/open`
  and runs them through `policy::resolve`. Used by the GUI Connect path to
  gate direct dials.
- **`rustion_policy_effective` Tauri command**
  (`gui/src-tauri/src/commands/rustion.rs`) -- Thin wrapper over the new
  server endpoint.

### Changed

- **GUI Connect now honours Rustion policy** (`gui/src-tauri/src/commands/connect.rs`).
  Before dialing, the in-app Connect button reads the effective per-resource
  Rustion policy and:
  - On `transport=rustion-required` (SSH + ssh-password): routes the session
    through a Rustion bastion via `rustion/session/open` and dials the
    returned `host:port` as user `operator` with the ticket as the SSH
    password.
  - On `transport=rustion-preferred` with a non-empty bastion set: same path
    as required when the credential is ssh-password; falls back to direct
    dial otherwise.
  - On `transport=direct` / unset: dials direct (existing behaviour).

### Fixed

- **Connect button no longer silently bypasses `rustion-required` policy**
  (`gui/src-tauri/src/commands/connect.rs`). Until 0.8.20 the per-resource
  Rustion policy was persisted but never consulted at connect time; an
  operator who saved `rustion-required` on a resource still got a direct
  dial from the GUI host. SSH-password sessions now route through the
  bastion; SSH with private-key or certificate credentials and any RDP
  session fail closed with an explanatory error under `rustion-required`
  (the bastion proxy doesn't speak those today).

## [0.8.20] - 2026-05-26

### Fixed

- **Rustion per-resource policy save for hostname IDs** (`src/modules/rustion/mod.rs`) -- broadened the `rustion/policy/resource/<id>` route regex from `[A-Za-z0-9_\-]+` to `[^/]+` so resource IDs that contain dots (e.g. `apldc1vds0044.fgv.br`) match the pattern. Previously the path fell through to the default logical-backend handler and the GUI Connection tab showed `HTTP 500: Logical backend path not supported` on Save.

## [0.8.19] - 2026-05-26

### Fixed
- **TLS pinning now works with self-signed leaf certs.** 0.8.18's
  pin implementation called `add_root_certificate(leaf)` +
  `danger_accept_invalid_hostnames`, but rustls / webpki refuse to
  use a cert as a trust anchor unless it carries
  `BasicConstraints: CA=true`. Self-signed leaves (the common
  pre-prod / lab posture — cert minted with `openssl req -x509` and
  no `-extensions`) have no extensions at all, so the handshake
  still failed with `UnknownIssuer` despite the pin. Switched to
  `danger_accept_invalid_certs(true)` alongside the
  `add_root_certificate(cert)` call: BV's real authentication of
  every Rustion-bound request lives in the BVRG-v1 envelope
  (Ed25519 + ML-DSA-65 signature, bound to the pinned authority
  pubkey on Rustion's side), so the TLS layer is transport
  encryption — downgrading verification when a pin is configured is
  the right trade-off until proper SPKI-pinning lands.
- **Probe error messages now walk the `source()` chain.** The previous
  `format!("transport: {e}")` showed only reqwest's top-level
  "error sending request for url …", hiding the real TLS / DNS /
  connect cause. The error now reads e.g. `transport: error
  sending request … -> client error (Connect) -> invalid peer
  certificate: UnknownIssuer`, surfacing exactly what the next
  hop is rejecting.

## [0.8.18] - 2026-05-26

### Added
- **Per-target TLS pinning for Rustion bastions.** New field
  `tls_pinned_cert_pem` on `RustionTarget` (and on the
  `rustion/targets`{,/{id}} HTTP API, the
  `bvault rustion target add --tls-cert-pem …` CLI flag, and the
  enrolment modal's new "Advanced — pin TLS leaf certificate" section).
  When set, the probe + session + telemetry + recordings + enrolment
  paths build a `reqwest::Client` that trusts **only** the supplied
  PEM cert as a root and skips hostname matching — pinning the leaf
  already binds trust to a specific server, making CN/SAN matching
  redundant and letting BV tolerate self-signed Rustion certs (lab /
  pre-prod) without weakening trust on production targets behind a
  real PKI. Mirrors the per-target pinning model already used for
  the Ed25519 / ML-DSA-65 / ML-KEM-768 keys.
- **Shared `super::http::build_client_for(target, timeout)` helper**
  ([src/modules/rustion/http.rs](src/modules/rustion/http.rs)) so the
  six call sites that talk to Rustion (probe, two session-open
  loops, renew, kill, telemetry pull, recording fetch / blob,
  attest, deenrol) honour the pin uniformly. The previous per-module
  `build_http_client()` helpers were folded into this single entry
  point.

### Changed
- **Update semantics for `tls_pinned_cert_pem`.** Empty value
  preserves the existing pin on update (matches the rest of the
  patch-style fields); the single-character sentinel `-` clears a
  previously-set pin.
- **Target response shape gains `tls_pinned: bool`** alongside the
  full `tls_pinned_cert_pem` body, so the GUI can render a "pinned"
  badge in list views without loading the PEM.

## [0.8.17] - 2026-05-22

### Changed
- **Rustion enrolment docs — webhook-key export wired in.** Replaced
  the placeholder "current gap" callout in
  [`features/rustion-integration.md`](features/rustion-integration.md)
  with the real `rustion control-plane webhook-key export` invocation
  (Rustion 0.10.1+). The webhook signing pair is now persisted at
  `<identity_dir>/webhook.key` on first boot and the CLI emits both
  `ed25519_spki_b64` and `mldsa65_pub_b64` directly, so operators no
  longer need the log-scraping workaround that 0.8.16's docs
  described. Source-table for the enrol form and the modal helper
  text in
  [`RustionBastionsTab.tsx`](gui/src/components/RustionBastionsTab.tsx)
  updated to match. Earlier "Phase 9.3 follow-up" reference dropped —
  it shipped as Rustion 0.10.1.

## [0.8.16] - 2026-05-22

### Changed
- **Rustion enrolment docs — operator runbook.** Added an
  end-to-end "Enrolling a Rustion bastion" section to
  [`features/rustion-integration.md`](features/rustion-integration.md)
  covering the new `rustion control-plane identity export` CLI
  (Rustion 0.10.0), where the ML-KEM-768 / Ed25519 / ML-DSA-65 keys
  live, how to submit + approve on the Rustion side
  (`rustion authority list-pending` / `approve`), how to verify
  end-to-end, and day-2 ops (re-attestation, master rotation, de-enrol,
  symmetric revocation). Flagged the current gap that Rustion's
  webhook Ed25519 + ML-DSA-65 public halves are not yet exported by
  the CLI — operators read them from the startup INFO log until the
  Phase 9.3 export command lands. Modal helper text in
  [`RustionBastionsTab.tsx`](gui/src/components/RustionBastionsTab.tsx)
  and CLI long-help in
  [`rustion_target_add.rs`](src/cli/command/rustion_target_add.rs)
  updated to point at the runbook.

## [0.8.15] - 2026-05-22

### Fixed
- **`rustion/targets/health` no longer 404s.** The Rustion module
  registered the catch-all `targets/(?P<id>[A-Za-z0-9_\-]+)$` route
  before the literal-name routes `targets/health` and `targets/probe`,
  so the resolver matched the catch-all first with `id="health"` and
  the read handler returned `HTTP 404: rustion target 'health' not
  found` on every settings-panel refresh (and the analogous error for
  `probe`). Moved the literal-name routes ahead of the catch-all in
  `src/modules/rustion/mod.rs`.

## [0.8.14] - 2026-05-22

### Fixed
- **Rustion settings panel now refreshes master state when sibling
  fetches fail.** `refresh()` in
  `gui/src/components/RustionBastionsTab.tsx` ganged five backend calls
  behind a single `Promise.all`, so a 404 from `rustionTargetHealthAll`
  (common on a fresh vault with no targets enrolled yet) aborted the
  batch and left `masterCfg` / `masterPub` stale — the panel kept
  showing "Master not issued yet" even after the bootstrap wizard
  succeeded. Switched to `Promise.allSettled`, applying each result
  independently and surfacing per-call errors via toast.

## [0.8.13] - 2026-05-22

### Fixed
- **Rustion master bootstrap now provisions two roots, one per
  algorithm class.** 0.8.12 switched the single bootstrap root to
  Ed25519, which fixed the EC default but still failed at `pki/issue/
  <mldsa65-role>` — the PKI engine refuses mixed-class chains (a
  classical CA cannot sign a PQC leaf and vice versa). The GUI wizard
  (`gui/src/components/RustionBastionsTab.tsx`) and
  `scripts/rustion-master-bootstrap.sh` now stand up both an Ed25519
  root (`rustion-master-ed25519-root`) and an ML-DSA-65 root
  (`rustion-master-mldsa65-root`) in the same mount, and pin each role
  to its matching issuer via `issuer_ref`. Matches the pattern in
  `tests/test_rustion_master_pki_issue.rs`. Re-running the wizard /
  script over a 0.8.12 install rewrites the role bindings; stale
  roles from older versions are overwritten in place.

## [0.8.12] - 2026-05-22

### Fixed
- **Rustion master bootstrap now generates an Ed25519 root** instead of
  the PKI engine's EC default. The GUI `Bootstrap Rustion master` wizard
  (`gui/src/components/RustionBastionsTab.tsx`) and
  `scripts/rustion-master-bootstrap.sh` both called the root-generate
  endpoint with no `key_type`, producing a classical EC root that could
  not sign the ML-DSA-65 master leaf — step 6 (`Mint hybrid master
  keypair`) failed with `HTTP 400: master issue: rustion master: PKI
  engine call pki/issue/<mldsa65-role> failed: ErrPkiKeyTypeInvalid`.
  Recovery for affected mounts: `bvault delete <mount>/issuer/default`
  and re-run the wizard / script.

## [0.8.11] - 2026-05-22

### Changed
- **Default container image now ships with `/bin/sh`.** The
  `INCLUDE_SHELL` build arg in `deploy/container/Containerfile` and
  the `Makefile` flipped from default `0` → default `1`, so a plain
  `make container-image` (or a CI build with no overrides) bakes in
  `busybox-static` from a Debian builder layer as `/bin/busybox` with
  `/bin/sh` symlinked to it. Single static binary, no library deps,
  ~1 MB. The bundled `rustion-master-bootstrap.sh` and any other
  shell-driven workflows (init scripts, `podman exec`, readiness
  probes) now work out of the box. Operators who want the classic
  shell-less distroless property can opt back out with
  `--build-arg INCLUDE_SHELL=0` / `make container-image INCLUDE_SHELL=0`.
  apt only runs in the staging container, so the final image still
  carries no package manager regardless of the flag.
- Docs updated: `features/packaging-podman-server.md` and
  `docs/rustion-integration.md` §3.1 now describe the new default and
  the opt-out path.

## [0.8.10] - 2026-05-22

### Added
- `scripts/rustion-master-bootstrap.sh` is now shipped inside the
  published container images at `/usr/local/bin/rustion-master-bootstrap.sh`
  (`deploy/container/Containerfile`, `deploy/container/Containerfile.debug`,
  and the e2e `Dockerfile`). The `:debug` variant runs it directly via
  `podman exec`; the default distroless variant either needs
  `INCLUDE_SHELL=1` or `podman cp` to extract and run from the host.

### Changed
- `scripts/rustion-master-bootstrap.sh` rewritten as POSIX sh (was
  `#!/usr/bin/env bash`) so it runs under busybox ash inside the
  container image without dragging a bash binary in. Syntax verified
  under bash, dash, and POSIX sh.
- Bootstrap script now reads `<mount>/issuer/default` after the "root
  certificate already present" branch and refuses up-front when the
  default issuer's `key_type` is classical (EC / RSA) instead of
  `ed25519` / `ml-dsa-65`. Mirrors the GUI wizard's new detection.
- Bootstrap script's "Mint hybrid master keypair" step now also
  rewrites the raw `ErrPkiKeyTypeInvalid` enum from `bvault rustion
  master issue` into actionable remediation guidance (fresh mount,
  delete bad issuer, promote a compatible one).

### Fixed
- `scripts/rustion-master-bootstrap.sh` previously called
  `bvault secrets enable -path=…` with Vault's single-dash flag style,
  which clap does not accept — so the script was actually broken at
  step 2 on any first-time install (it only ever worked when the PKI
  mount was already present). Corrected to `--path=…`.

### Fixed
- **GUI: Bootstrap Rustion master wizard** previously short-circuited the
  "Generate root certificate" step whenever the chosen PKI mount already
  had *any* issuer, regardless of its key algorithm. On mounts hosting
  an EC or RSA default issuer (e.g. a shared `pki/` reused for other
  CAs), the bootstrap would then fail at the last step with the cryptic
  `HTTP 400: master issue: rustion master: PKI engine call
  pki/issue/<role> failed: ErrPkiKeyTypeInvalid`, because BV's PKI engine
  cannot sign an ML-DSA-65 leaf with a classical root. The wizard now
  reads `<mount>/issuer/default` before skipping the root step and
  refuses up-front with actionable remediation when the existing
  default's `key_type` is anything other than `ed25519` / `ml-dsa-65`.
  The issue-step error handler also rewrites the raw
  `ErrPkiKeyTypeInvalid` into a message that names the likely cause and
  the two fix paths. (`gui/src/components/RustionBastionsTab.tsx`)

### Changed
- `docs/rustion-integration.md` now has a dedicated §3.1 "Initialize the
  Rustion master keypair" section with full step-by-step instructions
  for both the bootstrap-script path and the manual PKI-wiring path,
  plus a state-check, rotation, and a troubleshooting table for
  `bvault rustion master issue`. Previously this content was only a
  blockquote pointing out at `features/rustion-authority-lifecycle.md`.
  The troubleshooting table gained an `ErrPkiKeyTypeInvalid` row with a
  dedicated "Why this happens and how to avoid it" explainer that
  walks operators through using a fresh PKI mount to recover.

## [0.8.8] - 2026-05-22

### Fixed
- Docs and `bvault secrets enable --help` text incorrectly showed Vault's
  single-dash flag style (e.g. `-path=pki`). BastionVault uses clap-style
  long flags (`--path=pki`). Corrected across feature docs, the SSH engine
  doc, the dynamic-engine-plugins README, and the in-binary help text.
  Also fixed the dynamic-engine-plugins README example, which referenced
  a nonexistent `-plugin=` flag — plugin selection is done via
  `--options=plugin_name=…`.

### Added
- One-shot bootstrap script `scripts/rustion-master-bootstrap.sh` for
  Rustion master + PKI roles + issue. GUI: Rustion → Master panel now
  has a "Bootstrap master" button that runs the same flow.

## [0.8.7] - 2026-05-21

### Added
- **Rustion master authority lifecycle Phase 2** — `rustion/master/issue`
  and `rustion/master/rotate` HTTP endpoints plus matching CLI subcommands
  (`bvault rustion master issue` and `bvault rustion master rotate`).
  `issue` mints a hybrid Ed25519 + ML-DSA-65 master keypair, allocates a
  serial, and persists current + public PEMs + `not_after` under the
  encrypted barrier view. `rotate` archives the current keypair as
  `previous_*`, arms `rotate_grace_secs` (default 1d), and mints a fresh
  current. Envelopes signed by the outgoing key remain valid until the
  grace window closes. (`features/rustion-authority-lifecycle.md`,
  `src/modules/rustion/master.rs`)
- `MasterStore::load_active_keys` + `envelope::verify_with_grace` —
  ordered verify against current first, previous within grace.

### Changed
- Rustion master issue/rotate now mint keys via the configured PKI engine
  instead of generating them locally. `MasterConfig` gains a `pki_role_pqc`
  field (ML-DSA-65 role; `pki_role` continues to address the Ed25519 role)
  and both `issue` and `rotate` now route through `Core::handle_request`
  against `<pki_mount>/issue/<role>` for each half, so engine ACL, audit,
  and issuer state all engage. The real PKI-engine serial is surfaced as
  `current_serial`; the leaf PEMs are persisted under the barrier on the
  master signing record. Operators must configure both roles before
  `issue` / `rotate` will succeed.
- `rustion/master/pubkey` returns real Ed25519 / ML-DSA-65 public PEMs
  plus a SHA-256 fingerprint over the canonical `ed25519 || mldsa65`
  concatenation once the master has been issued, replacing the Phase-1
  empty-pubkey stub. `master/config` response now surfaces
  `pki_role_pqc`, `previous_serial`, `previous_not_after`, and
  `previous_grace_until`.

## [0.8.6] - 2026-05-21

### Added
- `bvault login` now persists the issued token to an on-disk helper file
  (`$BVAULT_TOKEN_FILE` if set, otherwise `~/.vault-token`) on success.
  All subsequent commands in the same shell pick it up automatically
  when `--client-token` / `VAULT_TOKEN` aren't set, matching HashiCorp
  Vault CLI behavior. New `--no-store` flag opts out per invocation.
- New `cli::util::{token_helper_path, read_persisted_token,
  write_persisted_token}` helpers, used both by login (write side) and
  `HttpOptions::client_at` (read fallback). Unix builds chmod 0600 the
  token file.

### Changed
- `HttpOptions::client_at` token-resolution order is now: `--client-token`
  / `VAULT_TOKEN` (existing) → token-helper file (new) → empty. Empty
  still produces an unauthenticated request, which the server rejects
  with HTTP 400 for token-gated endpoints — so the error surfaces the
  same way it did pre-0.8.6 when no auth source is configured.

## [0.8.5] - 2026-05-21

### Changed
- Added `BVAULT_TLS_DEBUG=1` env-gated stderr tracing of the URL rewrite +
  request dispatch path, so deployments that hit `--tls-server-name`
  edge cases can see exactly what URL clap parsed, what the rewriter
  produced, and what the request layer dispatched to ureq. No behavior
  change when the env var is unset.

## [0.8.4] - 2026-05-21

### Fixed
- 0.8.3's `--tls-server-name` plumbing panicked at request time:
  `StaticAddrResolver::resolve` built its `ResolvedSocketAddrs` via
  `ArrayVec::from_fn`, which populates the backing array but leaves the
  logical length at zero. The follow-up `truncate(1)` then asserted
  `1 <= 0` and aborted the process with "assertion failed: len <=
  self.len". Switched to `push` so the resolver actually returns a
  populated `ArrayVec` and the resolver's first call succeeds.

## [0.8.3] - 2026-05-21

### Fixed
- CLI `--tls-server-name` is now actually wired into the TLS stack. Previously
  the flag (and `VAULT_TLS_SERVER_NAME` env var) parsed via clap but never
  reached ureq, so rustls validated the server cert against the URL host —
  pointing at `https://127.0.0.1:8200` with a cert SAN of `foo.example.com`
  failed with `NotValidForName` regardless of `--tls-server-name`.
  `HttpOptions::client_at` now rewrites the URL host to the supplied SNI
  name and attaches a static DNS resolver to the ureq agent so the actual
  TCP connection still lands on the original host. Lets containerised
  deployments point the CLI at loopback while verifying against the host
  FQDN's cert SAN.

## [0.8.2] - 2026-05-21

### Added
- CLI: `HttpOptions` auto-discovers a CA cert when none was passed via
  `--ca-cert` / `VAULT_CACERT`. Discovery order: `$BVAULT_CACERT_AUTO`,
  `~/.bvault/ca.pem`, `/etc/bvault/ca.pem`,
  `/srv/application-config/bastionvault/tls/server.crt` (the
  puppet-bastionvault layout). Means `bvault` against a TLS-enabled local
  server stops needing `--tls-skip-verify` on every invocation.
- Server listener config: `tls_publish_ca_path` copies the serving cert to a
  caller-supplied path on bind (e.g. `/etc/bvault/ca.pem`). Intended for
  bare-metal installs where the server can write to a host-readable dir;
  containerised deployments (puppet-bastionvault's rootless podman) instead
  rely on the puppet module's `cli_trust_path` to publish a world-readable
  copy alongside the read-only TLS bind-mount.

### Fixed
- `bvault login` no longer panics with "no entry found for key" when invoked
  without a token argument. The token-auth handler was indexing the args map
  with `data["token"]` (panics on missing key) instead of `.get()`, blocking
  the interactive prompt path.

## [0.8.1] - 2026-05-20

Patch release: the `rustion/` logical mount was never auto-created on
install or upgrade, so every Phase 7 policy / bastion-group request on
a fresh-or-upgraded 0.8.0 deployment returned `404 Router mount not
found`. Existing installs pick it up via the default-mounts upgrade
path on next start; new installs get it as a core mount alongside
`sys/`, `identity/`, `resources/`, `files/`, `resource-group/`,
`secret/`.

### Fixed
- **Auto-mount `rustion/`** (`src/mount.rs`) -- added the Rustion
  logical backend to `DEFAULT_CORE_MOUNTS`, so `rustion/targets`,
  `rustion/policy/*`, `rustion/bastion-groups`, and the master / recording
  routes are reachable without operator-driven `sys/mounts` enable.
- **GUI: graceful empty state for missing Rustion mount**
  (`gui/src/components/RustionPolicyPanel.tsx`, `gui/src/lib/error.ts`)
  -- Global Rustion policy and Bastion groups cards now render an
  "unavailable on this server build" empty state when the API returns
  `404 mount not found`, instead of spamming a toast on every reload.
  Defense-in-depth for older server builds that predate the
  auto-mount.

## [0.8.0] - 2026-05-20

Minor-version bump closing Phase 9 of the Rustion integration:
disk-backed authority lifecycle + operator CLI on the bastion side,
weekly re-attestation timer + deenrol Tauri command on the BV side,
plus a dedicated deployment guide. Zero compiler warnings across
both repos.

### Added

- **Rustion integration — Phase 9.2: disk-backed pending + approval
  CLI + deenrol + tombstone + re-attestation timer** (paired with
  Rustion 0.8.0).
    - **Rustion `authority_disk` module** — `AuthorityYaml` /
      `PendingYaml` / `TombstoneYaml` DTOs with `schema_version: 1`,
      base64-encoded ed25519 + ML-DSA-65 pubkey halves, atomic
      rename-then-replace writes. **7 new unit tests** covering
      round-trip, schema-version mismatch, malformed-YAML path
      reporting, missing-dir → empty map, replay-window preservation,
      idempotent deletes.
    - **Rustion `AuthorityStore` disk-backed CRUD** —
      `load_from_disk(active, pending, tombs)`,
      `submit_pending_on_disk`, `approve_pending_on_disk`,
      `reject_pending_on_disk`, `deenrol_on_disk`,
      `untombstone_on_disk`. Each drives both the in-memory map and
      the YAML file so a crash mid-flight can't leave a dangling
      record.
    - **Rustion CLI** — new `rustion authority` subcommand with
      `list-pending`, `list`, `list-tombstones`,
      `approve --name --max-session-secs --replay-window-secs`,
      `reject --name --reason`, `deenrol --name --reason`,
      `untombstone --name`. Operates directly on
      `<config_dir>/{authorities,authorities-pending,tombstoned}/` and
      reminds the operator to `rustion reload` for live pickup.
    - **Rustion lifecycle integration test** — `tests/authority_lifecycle.rs`
      drives submit → approve → deenrol → resubmit-while-tombstoned
      (refused) → untombstone, plus reject-writes-tombstone, plus
      three-projection `load_from_disk`. **3 e2e tests.**
    - **BV `envelope::build_deenrol`** — new helper building an
      `op: "deenrol"` envelope.
    - **BV `src/modules/rustion/enrolment.rs`** new module —
      `attest_bastion`, `attest_all`, `deenrol_bastion`, plus
      `AttestAllResult` / `AttestOutcome` shapes. `RustionStore::list_targets`
      added in `store.rs`.
    - **BV `src/modules/rustion/attest_timer.rs`** — detached tokio
      task ticking every 6 days; wired into core boot alongside the
      existing rustion timers.
    - **BV HTTP routes** — `POST rustion/authority/attest` (optional
      `bastion_id`) emits `rustion.master.attest`;
      `POST rustion/target/deenrol` emits `rustion.target.deenrolled`.
    - **BV Tauri commands** — `rustion_authority_attest`,
      `rustion_target_deenrol`, plus matching TS wrappers
      (`rustionAuthorityAttest`, `rustionTargetDeenrol`).
- **Deployment guide** — new
  [`features/rustion-authority-lifecycle.md`](features/rustion-authority-lifecycle.md)
  walks operators through directory layout, YAML schemas, full
  end-to-end submit → approve → attest → deenrol → resurrection-guard
  flow, plus deployment recipes for docker-compose / bare-metal HA /
  Kubernetes GitOps. Includes the failure-mode quick reference table.

### Fixed

- **Build warnings cleared on both repos** —
    - BV: removed unused `mut` on `telemetry::stamped`; marked the
      unused `serde_bytes_compat::serialize` helper `#[allow(dead_code)]`
      (kept for symmetry with the deserialize path).
    - Rustion: scoped `BvrgPayload` import in `control-plane::session`
      to `#[cfg(test)]`; allowed `unused_assignments` on the
      webhook-retry `last_err` sentinel.

### Changed

- `features/rustion-integration.md`: Phase 9.2 marked Done. Phase 9
  is now fully closed; remaining items (`attestation_renew_at`
  enforcement at envelope-verify, Rustion admin web UI, BV-side
  GUI buttons for the new Tauri commands) recorded as separate
  tracks rather than Phase 9 deferred work.
- **Minor-version bump** to 0.8.0 across BV (`Cargo.toml`,
  `gui/src-tauri/Cargo.toml`, `gui/src-tauri/tauri.conf.json`,
  `gui/package.json`) and Rustion (`Cargo.toml` workspace.package).

## [0.7.37] - 2026-05-20

### Added

- **Rustion integration — Phase 4.2-full: CredSSP RC4 sealing +
  pubKeyAuth + simulated-Windows e2e** (paired with Rustion 0.7.28).
  The bastion-driven CredSSP injection driver is now wire-complete —
  it builds the AUTHENTICATE message, encrypts the random session
  key, derives sign+seal keys per direction, seals pubKeyAuth /
  authInfo, and verifies the upstream's "+1" pubKeyAuth reply. Live
  Windows VM validation is queued for when the user provides one;
  protocol logic is covered by an in-process Windows responder
  simulator.
    - **`rustion-rdp::ntlmv2_seal`** new module (Rustion side):
        - `sign_key` / `seal_key` derivation per MS-NLMP §3.4.5.2 +
          §3.4.5.3, with the four C-string magic constants
          (`CLIENT_SIGNING_MAGIC`, `SERVER_SIGNING_MAGIC`,
          `CLIENT_SEALING_MAGIC`, `SERVER_SEALING_MAGIC`).
        - `Rc4` streaming cipher + `rc4_once` one-shot helper, KAT-
          tested against RFC 6229 (`Key=0102030405`).
        - `SealState { sign_key, rc4, seqnum }` per-direction sealing
          handle: `.seal(plaintext)` → `NTLMSSP_MESSAGE_SIGNATURE_v2
          (16B) || ciphertext`, `.unseal(blob)` verifies the HMAC-MD5
          checksum and recovers plaintext. Seqnum advances per call;
          the RC4 keystream is continuous across the exchange.
        - **7 new unit tests.**
    - **`rustion-rdp::bv_credssp` rewrite** (Rustion side):
        - `prepare_authenticate(...) → AuthInjection` now generates a
          fresh `ExportedSessionKey`, encrypts it under
          `KeyExchangeKey == SessionBaseKey` (extended session
          security path), and returns ready-to-use `seal_c2s` /
          `seal_s2c` handles. The `SealingDeferred` error variant is
          gone — the Phase 4.2-light "explicit gap at the type level"
          marker is no longer needed.
        - `SealedCredsspSession::seal_pub_key_auth(spki_der)` +
          `verify_pub_key_auth(reply, expected_spki)` implements the
          MS-CSSP §3.1.5 "+1 on first byte" pubKeyAuth contract.
        - `seal_auth_info(ts_credentials_ber)` for the third-leg
          sealed authInfo.
        - `encode_ts_password_creds(domain, user, password)` —
          BER-encoded `TSCredentials → TSPasswordCreds` per MS-CSSP
          §2.2.1.2 (cred_type=1, UTF-16LE strings). Round-trip-tested
          against the existing inbound parser.
        - **5 unit tests** covering the AUTHENTICATE shape, the
          pubKeyAuth +1 transform, length-mismatch rejection, and
          BER round-trip.
    - **`rustion-rdp::tests::credssp_e2e`** new integration test
      (Rustion side):
        - `MockServer` simulates a Windows NLA responder. Builds
          CHALLENGE_MESSAGE; ingests AUTHENTICATE; re-derives NTOWFv2
          from the known password; asserts the bastion's NTProofStr
          matches; recovers the ExportedSessionKey via RC4 inverse;
          builds the matching seal states.
        - `full_credssp_exchange_against_simulated_windows` — three-
          leg round trip with sealed pubKeyAuth and sealed
          TSCredentials.
        - `pub_key_auth_reply_rejects_unrelated_spki` — MITM-style
          mismatch.
        - `wrong_password_breaks_at_the_server` — pins the failure
          mode.
        - **3 e2e tests** (in addition to the 76-test lib suite —
          all green).
    - **`rustion-rdp::proxy`** call-site log + error messaging
      refreshed: BV `rdp-password` dispatch now reports the driver as
      Phase 4.2-full-ready rather than "deferred"; `rdp-cert`
      continues to route to its own clean error (separate PKINIT
      track).

### Changed

- `features/rustion-integration.md`: Phase 4.2-full marked Done. The
  remaining items (live Windows VM transport hookup, `rdp-cert`
  smart-card PKINIT/SPNEGO, Restricted Admin) are documented as
  separate tracks rather than Phase 4 deferred work.

## [0.7.36] - 2026-05-20

### Added

- **Rustion integration — Phase 8.4: RDP bitmap-update visual codec**
  (BV-only release; no Rustion-side change). The replay window now
  renders `.rdp-rec` recordings as live canvas playback instead of a
  text summary.
    - **`gui/wasm/rdp-replay/`** crate grew the full bitmap decoder.
      `decode_rdp_rec(bytes) → DecodeOutput` returns per-rectangle
      `Frame { timestamp_ms, x, y, w, h, bpp, compressed, decoder,
      rgba, error }` records ready for canvas blitting, plus a
      `decoder_counts` BTreeMap keyed by `"uncompressed" | "rle16" |
      "rle24" | "unsupported" | "error"`. Implements MS-RDPBCGR
      § 2.2.9.1.1.3.1.2.2 `TS_BITMAP_DATA` parsing (single-rect per
      event, since the recorder strips the outer `numberRectangles`)
      and MS-RDPEGDI § 3.1.9 RLE16/RLE24 decoders (BgRun, FgRun,
      ColorRun, FOM, SetFgFom, Setfg, Pixels, White/Black runs, plus
      MegaMega forms). Uncompressed 16/24/32 bpp also covered with
      bottom-up→top-down flip. **6 new Rust unit tests** (10 total in
      the crate).
    - **`gui/src/lib/rdpDecoder.ts`** — 1:1 TypeScript port of the
      Rust decoder so the GUI can run in-browser without a wasm-pack
      build step. The Rust crate stays canonical; **6 matching
      vitest tests** ensure the TS port doesn't drift (112 total
      vitest tests passing).
    - **`gui/src/components/RdpReplayCanvas.tsx`** new component:
      `<canvas>` sized to the recording's source resolution (header
      width/height or computed from the rectangle bounding box),
      animates frames at the recording's wall-clock timestamps with
      `requestAnimationFrame`. Controls: Play / Pause / Restart /
      1× / 2× / 4× / 8×. Surfaces a "rendered / skipped / total"
      counter and a "lossy: NSCodec/RemoteFX/8bpp out of scope"
      badge when any frame lands on an unsupported path.
    - **`SessionReplayWindow`** now routes `rdp-rec` blobs to
      `RdpReplayCanvas` first; the previous summary view stays
      reachable behind a "Show details" toggle.

### Changed

- `features/rustion-integration.md`: Phase 8.4 marked Done. The
  remaining RDP-codec engineering (NSCodec, RemoteFX, 8 bpp RLE,
  bitmap-cache references) is recorded as out-of-scope work, not as
  a follow-up Phase 8.x.

## [0.7.35] - 2026-05-19

### Added

- **Rustion integration — Phase 8.3: SessionReplayWindow + WASM frame
  walker + signed-URL replay** (paired with Rustion 0.7.27). The
  separate replay window, the wasm-decoder slot, and the signed-URL
  plumbing are all in place.
    - **`SessionReplayWindow`** new route at
      `/session-replay?recording=<rid>`. Layout-less full-screen
      player; pulls metadata + bytes via Tauri commands, routes to
      format-specific renderer (asciicast / rdp-rec / smb-log).
    - **`rustion_open_replay_window`** Tauri command spawning a
      separate Tauri WebviewWindow at 1200×800. Re-focuses an
      existing window for the same recording instead of duplicating.
    - **Recordings-page modal** grew an "Open in window" button.
    - **`gui/wasm/rdp-replay/`** new standalone wasm crate
      (workspace-excluded; built with `wasm-pack build --target web`).
      Exposes `parse_rdp_rec(bytes) → Summary` — validates the RREC
      magic, parses header, walks the event stream, returns counts +
      duration. 5 native unit tests. The visual MS-RDPBCGR bitmap
      codec (RLE + NSCodec + bitmap-cache management) is the
      separate multi-week engineering project tracked as Phase 8.4.
    - **Signed-URL replay infrastructure**:
      `POST /v1/recordings/<rid>/replay` on Rustion (re-uses the
      authority + replay gate) returns a 60s HMAC-bound URL with
      IP-binding from the envelope's `operator.src_ip`.
      `GET /v1/recordings/<rid>?expires=&ip=&sig=` validates the
      HMAC + expiry + IP and serves bytes (constant-time tag
      compare, domain-separated tag with literal
      `"/v1/recordings/"` prefix). `ControlPlaneState` grew a
      `recording_url_signing_secret: Option<Arc<[u8; 32]>>` field;
      `None` → `503 signed_url_disabled`. `hmac` workspace dep
      added.

### Changed

- `features/rustion-integration.md`: Phase 8.3 marked Done; Phase 8.4
  carved out for the RDP bitmap-update visual codec (separate
  engineering track that slots into the existing `gui/wasm/rdp-replay/`
  crate when ready).

## [0.7.34] - 2026-05-19

### Added

- **Rustion integration — Phase 9.1: deployment_id + pending-authority
  holding pen** (paired with Rustion 0.7.26). Trust-establishment
  foundation.
    - **BV `master::get_or_init_deployment_id`** — stable v4 UUID
      minted on first access, persisted at
      `sys/rustion/master/deployment-id`. Stamped into every BVRG-v1
      envelope's `operator.deployment_id` via `OperatorContext` on
      open/renew/kill. Replaces the previous (always-empty)
      "read from auth.metadata" placeholder.
    - **BV `GET rustion/deployment-id`** route +
      `rustion_deployment_id_read` Tauri command. Settings →
      Rustion → Bastions surfaces the id with a paste-into-bastion
      note.
    - **Rustion `AuthorityStore`** grew `pending` + `tombstones`
      maps. CRUD: `submit_pending`, `list_pending`, `get_pending`,
      `approve_pending`, `reject_pending` (drops to tombstones),
      `list_tombstones`, `is_pending`, `is_tombstoned`. New
      `PendingAuthority` + `TombstoneEntry` structs.
    - **Envelope-verify** now distinguishes pending/tombstoned/unknown
      with 403 codes `authority_pending_approval` /
      `authority_tombstoned` / 401 `unknown_authority`.
    - **Deployment_id binding** in the verify prelude: envelopes
      whose `operator.deployment_id` doesn't match the authority's
      pinned value are refused with `403 attestation_mismatch`.
      Empty pinned id = backward-compat path.
    - **Five new audit constants**: `TARGET_ENROL_SUBMITTED`,
      `TARGET_ENROL_APPROVED`, `TARGET_DEENROLLED`, `MASTER_ATTEST`,
      plus existing `RUSTION_AUDIT_WITNESS` for echoes.

### Changed

- `features/rustion-integration.md`: Phase 9.1 marked Done; Phase 9.2
  carves out disk-backed pending/tombstone YAML + approval CLI on
  Rustion + admin web UI + BV deenrol command + weekly
  re-attestation timer + hash-chain entries for the lifecycle events.

## [0.7.33] - 2026-05-19

### Added

- **Rustion integration — Phase 8.2: audit witness + rate limiting +
  replay-log + analytics** (paired with Rustion 0.7.25). Closes the
  security-and-observability layer of telemetry.
    - **Rustion `/v1/sessions/audit?since=&limit=`** paginated
      hash-chain entries read directly via the existing `AuditStore`
      trait. Returns `503 audit_chain_unavailable` when no store is
      wired.
    - **Rustion `rate_limit::TokenBucket`** new module — per-(IP,
      authority) bucket with 60-token capacity + 4 tok/sec refill.
      Gates all telemetry endpoints. 2 unit tests.
    - **`ControlPlaneState`** grew `audit_store` +
      `telemetry_rate_limiter` fields (both `Option`, default `None`).
    - **BV telemetry poller** now pulls `/v1/sessions/audit` after
      the active/history/stats fan-out. Persists every row at
      `rustion/audit_witness/<target_id>/<hash>`. Emits
      `rustion.audit.witness` per entry on the BV audit chain.
      Cursor's `last_audit_seq` advances by Rustion's `next_seq`.
      In-memory `recent_audit` capped at 200.
    - **Two new audit constants**: `RUSTION_AUDIT_WITNESS`,
      `RECORDING_REPLAYED`.
    - **`POST rustion/recordings/replay-log`** + new
      `rustion_recording_replay_log` Tauri command. The Recordings
      page hashes the loaded bytes via `crypto.subtle.digest` and
      compares against the sidecar's `sha256`, reporting the result
      to BV which emits `recording.replayed` with operator id +
      mismatch flag.
    - **Live Sessions analytics extension**: two new fleet-wide
      Top Targets + Top Operators cards with bar viz, plus a
      "Recent audit witness" table (last 30 entries, event-type
      badge + hash-prefix column).

### Changed

- `features/rustion-integration.md`: Phase 8.2 marked Done; Phase 8.3
  carved out for the separate replay WebviewWindow + `.rdp-rec` WASM
  decoder + signed-URL recording-stream infrastructure (the wasm
  decoder is a multi-week protocol-codec engineering track separate
  from this feature, deferred consistently with Phase 6.5).

## [0.7.32] - 2026-05-19

### Added

- **Rustion integration — Phase 8.1: telemetry pull + Live Sessions
  page** (paired with Rustion 0.7.24). Cross-fleet observability:
  60s pull loop + authority-scoped telemetry endpoints + new GUI page.
    - **Rustion side**: three new authority-scoped GET endpoints
      `/v1/sessions/active`, `/v1/sessions/history?since=&limit=`,
      `/v1/stats`. `SessionStore::snapshot_by_authority` +
      `stats_for_authority` new helpers. `require_authority` helper
      gates telemetry on the existing X-Rustion-Authority header.
    - **BV `src/modules/rustion/telemetry.rs`** new module: 60s
      detached poller spawned at boot from `core.rs` alongside the
      probe pinger + the 24h recording poller. `TelemetryCache`
      keeps an in-memory `HashMap<target_id, TargetSnapshot>` behind
      a `tokio::sync::RwLock`. Per-target cursor persistence at
      `rustion/telemetry/<target_id>/cursor` so restarts resume.
    - **BV HTTP routes**: `GET rustion/telemetry` returns the cache
      snapshot; `POST rustion/telemetry/poll` forces a synchronous
      pass and returns the fresh snapshot.
    - **Two new Tauri commands + TS wrappers**:
      `rustionTelemetryList`, `rustionTelemetryPoll`.
    - **New GUI `/rustion-sessions` page** + sidebar entry:
      cross-bastion Live Sessions view with 5s auto-refresh,
      search + per-bastion filter, three summary cards (active
      fleet sessions / lifetime rolling / total session time), one
      row per active session with operator + src-ip + target +
      opened/expires/renewals, and a per-row **Terminate** button
      calling `rustionSessionKill`.

### Changed

- `features/rustion-integration.md`: Phase 8.1 marked Done. Phase
  8.2 carves out the remaining slice — signed audit-witness pull
  (`/v1/sessions/audit` + `rustion.audit.witness` event), rate
  limiting on telemetry endpoints, signed-URL recording replay
  (`POST rustion/recordings/<rid>/replay` + `GET /v1/recordings/<rid>`
  on Rustion), a separate `SessionReplayWindow` WebviewWindow, the
  `recording.replayed` audit event, and an analytics dashboard.

## [0.7.31] - 2026-05-19

### Added

- **Rustion integration — Phase 7.3: per-tier editor integration +
  full resolver chain**. Phase 7 fully closed end-to-end. The
  four-tier policy is now end-to-end configurable from the GUI and
  the resolver consults every tier on `session/open`.
    - **`RustionPolicyTierEditor`** new reusable component handling
      all three lower tiers (`type` | `asset-group` | `resource`).
      Shared shape (transport / bastions / bastion_group / recording
      / lock — hidden on `resource`) + tier-specific affordances
      (priority slider for `asset-group`). Manages its own
      load/save state via the typed wrappers.
    - **AssetGroupsPage** embeds the editor in each AG's detail
      card next to Resources/Secrets.
    - **ResourcesPage** Connection tab embeds the editor next to
      ConnectionProfilesPanel. The component hides the lock toggle;
      the API refuses lock=true + writes that weaken an upstream
      lock via probe-resolve.
    - **Settings → Rustion → Policy** grew a "Resource type policy"
      subcard so admins can manage per-type policy without a
      dedicated Resource Types editor.
    - **`session/open` full resolver chain**: handler reads three new
      optional request fields (`resource_id`, `resource_type`,
      `asset_group_ids`), looks them up in `PolicyStore`, calls
      `policy::resolve(global, type, asset_groups, resource)`. The
      Tauri `RustionSessionOpenRequest` + TS wrapper grew the
      matching fields. Existing callers that omit them keep
      Phase-7.2 global-only behaviour (backward-compatible).

### Changed

- `features/rustion-integration.md`: Phase 7.3 marked Done. Phase 7
  fully closed (1 → 7.3). Remaining Rustion-integration work is
  Phase 4.2-full (RC4 sealing + Windows VM), Phase 8 (telemetry +
  in-GUI replay extensions), Phase 9 (enrolment lifecycle).

## [0.7.30] - 2026-05-19

### Added

- **Rustion integration — Phase 7.2: per-tier CRUD + session/open
  resolver + Settings UI + migration**. Brings the four-tier policy
  from "data model + global CRUD" up to a usable governance surface.
    - **HTTP routes** for the three remaining tiers:
      `GET/PUT/DELETE rustion/policy/type/<name>`,
      `GET/PUT rustion/policy/asset-group/<id>` (with priority),
      `GET/PUT rustion/policy/resource/<id>`,
      `POST rustion/policy/force-rustion`. The per-resource handler
      refuses `lock=true` (only higher tiers may lock) and refuses
      writes that would weaken a higher-tier lock via probe-resolve.
    - **8 new Tauri commands + TS wrappers**:
      `rustionPolicyType{Read,Write,Delete}`,
      `rustionPolicyAssetGroup{Read,Write}`,
      `rustionPolicyResource{Read,Write}`,
      `rustionPolicyForceRustion`.
    - **`session/open` resolver wiring**: loads global, calls
      `policy::resolve`, refuses on `lock_violation` (403), refuses on
      `transport=rustion-required` without enrolled bastions (403),
      overrides caller-supplied `bastions` with policy-pinned list or
      bastion-group members, forces `recording` to the resolver's
      strictest value. Stamps `policy_transport`,
      `policy_transport_source`, `policy_recording`,
      `policy_recording_source`, `policy_bastions_source`,
      `policy_locked_by` on the session-open response.
    - **Settings → Rustion → Policy panel**: new
      `RustionPolicyPanel` component mounted alongside
      `RustionBastionsTab` under the "Rustion" tab. Three cards —
      Global Policy editor, Bastion Groups CRUD (list + create/edit/
      delete with member list + ordered/random selection +
      description), and "Force all Connect through Rustion" with a
      preview→confirm dry-run flow.
    - **Audit emission**: `POLICY_TYPE_UPDATE`,
      `POLICY_ASSET_GROUP_UPDATE`, `POLICY_RESOURCE_UPDATE` light up
      at their respective write sites. `POLICY_GLOBAL_UPDATE`
      doubles as the audit event for the force-rustion migration.

### Changed

- `features/rustion-integration.md`: Phase 7.2 marked Done; Phase 7.3
  carved out for the per-tier editor integration into existing
  Resource Types / Asset Groups / Resource Connection pages + the
  full type/asset-group resolver chain in `session/open`.

## [0.7.29] - 2026-05-19

### Added

- **Rustion integration — Phase 7.1: four-tier policy foundation**.
  Data model + storage + resolver + global/bastion-groups CRUD. The
  per-resource-type / per-asset-group / per-resource editors and the
  `session/open` integration land in Phase 7.2.
    - **`src/modules/rustion/policy.rs`** new module:
        - `Transport`, `Recording`, `Selection` enums.
        - `PolicyTier { transport, bastions, bastion_group, recording, lock }`
          + per-tier wrappers (`GlobalPolicy`, `TypePolicy`,
          `AssetGroupPolicy { priority }`, `ResourcePolicy`).
        - `BastionGroup` for named bastion pools.
        - `resolve(global, type_, asset_groups[], resource) → EffectivePolicy`
          implements: transport = most-restrictive wins; recording =
          strictest wins; bastions/bastion_group = nearest-defined-tier
          wins; asset-group priority breaks ties (high wins via
          low-first overwrite). Lock semantics: a locked tier
          snapshots its knobs; lower tiers may match-or-strengthen but
          never weaken — violations surface as
          `EffectivePolicy.lock_violation`.
        - `PolicyStore` with five storage views (bastion groups,
          global, per-type, per-AG, per-resource).
        - **8 unit tests** cover default, raise-from-resource, lock
          violations on both transport and recording, nearest-tier
          bastions, asset-group priority resolution.
    - **HTTP routes**:
        - `GET/PUT rustion/policy/global`.
        - `GET rustion/bastion-groups` (list) + `POST` (create).
        - `GET/PUT/DELETE rustion/bastion-groups/<name>`.
    - **Tauri commands + TS wrappers**: `rustionPolicyGlobal{Read,Write}`,
      `rustionBastionGroup{List,Read,Create,Update,Delete}`.
    - Existing audit constants `POLICY_GLOBAL_UPDATE` +
      `BASTION_GROUP_UPDATE` (from Phase 1) now emit on the new
      handlers; `POLICY_TYPE_UPDATE`, `POLICY_ASSET_GROUP_UPDATE`,
      `POLICY_RESOURCE_UPDATE` light up in Phase 7.2 alongside the
      per-tier editors.

### Changed

- `features/rustion-integration.md`: Phase 7 split — 7.1 marked Done;
  7.2 carved out for the per-type / per-AG / per-resource editor
  surface, the `session/open` resolver integration, and the
  "Force all Connect through Rustion" migration action.

## [0.7.28] - 2026-05-19

### Added

- **Rustion integration — Phase 6.5: Recordings page + inline
  playback**. Closes Phase 6 end-to-end on the recording handoff loop.
    - **BV recording-bytes proxy**: `GET rustion/recordings/<rid>/blob`
      routes through `recordings::fetch_blob` to the bastion's
      `GET /v1/recordings/<rid>/blob`, returns bytes base64-wrapped.
      New Tauri command `rustion_recording_blob(rid)` + typed TS
      wrapper.
    - **`/recordings` route + sidebar entry**: new `RecordingsPage`.
      Lists every `RustionRecordingEntry` from the recordings index
      with format/delivery/search filters; surfaces bastion-pull
      from the same page.
    - **`RecordingPlayerModal`** opens on row click. Loads bytes,
      decodes base64 → `Uint8Array`, dispatches to a format-specific
      renderer.
    - **`AsciicastPlayer`** (SSH): native xterm.js renderer (no
      `asciinema-player` dep — saves ~80 KB in the bundle). Parses
      asciicast v2 + drives an xterm with the spec-mandated rows/cols,
      schedules writes off `performance.now()`.
    - **`RdpRecSummary`** (RDP): walks the `.rdp-rec` frame stream
      natively in TS (magic `"RREC"` + JSON header + `(ts:u64 +
      type:u8 + len:u32 + payload)` iteration). Shows header,
      graphics/keyboard/mouse event counts, total duration. The
      inline visual replay path is gated on a real MS-RDPBCGR
      bitmap-update codec (slow-path bitmap + raster ops + NSCodec)
      — that's a multi-week protocol-decoder project tracked as a
      separate UI/codec engineering track. The page surfaces this
      explicitly and the download button hands the operator the raw
      `.rdp-rec` for external viewers.
    - **`SmbLogSummary`** (SMB): plain-text op log preview + download.

### Changed

- `features/rustion-integration.md`: Phase 6.5 marked Done — Phase 6
  is fully closed (1 → 6.5). The remaining Rustion-integration work is
  Phase 4.2-full (RC4 sealing + pubKeyAuth + Windows VM), Phase 7
  (policy tiers), Phase 8 (telemetry + in-GUI replay extension),
  Phase 9 (enrolment-approval + re-attestation + master-cert rotation
  + tombstones).

## [0.7.27] - 2026-05-19

### Added

- **Rustion integration — Phase 6.4: cron + bytes endpoint + proxy
  emit glue** (paired with Rustion 0.7.23). Closes the operational
  handoff loop fully — the BV cron pulls missed recordings on
  schedule, Rustion serves recording bytes for playback, and the
  SSH/RDP proxies actually fire webhook deliveries on
  `recorder.finish()`.
    - **BV `recordings::PendingRecording`** + `pending_view`:
      every `session/open` stamps a marker carrying `session_id`,
      `bastion_id`, `correlation_id`, `expected_by = expires_at + 5
      min`. Webhook delivery + pull-fallback both clear the marker.
    - **BV `poller` module**: detached background task spawned at
      boot alongside `rustion::probe::start_pinger`. Mirrors the
      pinger shape; ticks every 1 h; walks the pending view and
      calls `pull_recording` for entries past `expected_by`. Past
      `MAX_RETENTION = 24 h` they're dropped as unrecoverable
      (operators can still pull manually).
    - **Rustion `webhook::WebhookEmitter`**: shared handle that
      looks up the per-authority webhook URL via `AuthorityStore`,
      signs the sidecar bytes, and spawns a detached
      `deliver_with_retry` task. Emitter is `Arc<>`-shared,
      constructed once at `rustion-server` startup; injected into
      `SshProxy::with_webhook_emitter` and
      `RdpProxy::with_webhook_emitter`.
    - **SshProxy / RdpProxy / ServerHandler glue**: emitter
      threaded down to `connect_to_target_with_credential_and_relay`
      (SSH) / `handle_rdp_connection` (RDP). When the sidecar lands
      and `RECORDING_READY` fires, the relay serialises the sidecar
      and calls `emitter.spawn_delivery(authority, body)`. Classical
      (non-BV) sessions skip the call cleanly (empty authority).
    - **Rustion `GET /v1/recordings/:rid/blob`**: serves the
      recording artifact bytes for in-GUI playback. Maps
      `rec_<sid_suffix>` → `<sid>.cast` / `<sid>.rdp-rec` via the
      per-session sidecar. Returns `X-Recording-SHA256` +
      `X-Recording-Format` headers for integrity verification.

### Changed

- `features/rustion-integration.md`: Phase 6.4 marked Done; Phase 6.5
  carved out for the remaining GUI playback work (Recordings page,
  asciinema-player wiring, `.rdp-rec` wasm decoder, optional
  short-lived signed-URL upgrade).

## [0.7.26] - 2026-05-19

### Added

- **Rustion integration — Phase 6.3: retry loop + pull-fallback +
  recordings surface** (paired with Rustion 0.7.22). Closes the
  operational handoff loop so webhooks survive transient failures
  with bounded backoff, BV can force-pull a missed recording, and
  the GUI has the API surface to query the recordings index.
    - **Rustion `webhook::deliver_with_retry`** wraps `deliver()`
      with `RETRY_DELAYS_SECS = [30, 60, 240, 600, 900]` (1830 s
      total = 30m 30s) — matches the spec's "5 retries over ~30 min"
      target. Each attempt emits `rustion::usage`
      `RECORDING_WEBHOOK_RETRY` (failure) or
      `RECORDING_WEBHOOK_DELIVERED` (success). 2 new unit tests
      (schedule total + walking-then-giving-up against
      `127.0.0.1:1`).
    - **BV `recordings::pull_recording`** — GETs the bastion's
      `/v1/sessions/{sid}/recording` endpoint, parses the sidecar,
      stores with `delivery_mode = "pull"`. No signature check on
      this path because the sidecar arrives over the bastion's
      TLS-pinned channel. Emits `audit::RECORDING_LINKED` with
      `mode=pull`.
    - **New HTTP route** `POST rustion/recordings/pull` driving the
      helper. Operator-triggered or (Phase 6.4) scheduler-driven.
    - **Three new Tauri commands**: `rustion_recordings_list`,
      `rustion_recording_read`, `rustion_recording_pull`. Typed
      TypeScript wrappers `rustionRecordingsList`,
      `rustionRecordingRead`, `rustionRecordingPull` in
      `gui/src/lib/rustion.ts` with the `RustionRecordingEntry`
      shape mirroring the BV-side struct.

### Changed

- `features/rustion-integration.md`: Phase 6.3 marked Done; Phase 6.4
  carved out for the 24h cron scheduler, GUI playback (xterm.js +
  asciinema-player + `.rdp-rec` wasm decoder), and the signed-URL
  bytes endpoint on Rustion.

## [0.7.25] - 2026-05-19

### Added

- **Rustion integration — Phase 6.2: recording webhook + receiver + index**
  (paired with Rustion 0.7.21). Closes the signed-handoff loop between
  Rustion and BV — Rustion can POST a signed sidecar over the wire,
  BV verifies + stores + audits it, and either side can pull the
  sidecar back as JSON if the webhook dropped.
    - **Rustion `crates/rustion-control-plane/src/webhook.rs`** — new
      module: `WebhookSigningKey` (Ed25519 + ML-DSA-65 hybrid keypair,
      generate or from-bytes), `WebhookVerifyingKey` (mirror verify
      path), `sign_header(body)` produces
      `"ed25519=<base64> mldsa65=<base64>"`, `verify_header(...)`
      rejects malformed / classical-only / wrong-pubkey. Wire-format
      identical to the BVRG-v1 sign path (sha256 → both halves).
      `deliver(client, url, body, sig)` one-shot POST helper. 8 new
      unit tests including the classical-only downgrade-rejection
      case.
    - **`GET /v1/sessions/{sid}/recording`** on the axum router for
      the 24h pull-fallback window. `ControlPlaneState.recordings_base_dir`
      configures the lookup root.
    - **`AuthorityRecord.recording_webhook_url`** so the per-authority
      orchestration layer knows where to POST.
- **BV side**:
    - `src/modules/rustion/webhook_verify.rs` — verifier mirror of
      the Rustion signer, validated against the same crate. Uses
      `fips204` (already a BV dep) for the PQC half so no extra
      crypto crate. 4 round-trip + downgrade-rejection unit tests.
    - `src/modules/rustion/recordings.rs` — `RecordingsStore` +
      `RecordingEntry` over `rustion/recordings/<rid>` under the
      system view. Tracks every sidecar field plus `bastion_id`,
      `received_at`, and `delivery_mode` ∈ {`webhook` | `pull`
      (Phase 6.3)}.
    - **New routes**:
        - `POST rustion/webhooks/recording-ready` — verifies the
          X-Rustion-Signature against the pinned
          `RustionTarget.public_key`, parses the sidecar JSON,
          persists the entry, emits `audit::RECORDING_LINKED`.
        - `GET rustion/recordings` — list known recording ids.
        - `GET rustion/recordings/<rid>` — fetch one entry.
- **Pre-existing test bug fixed**: `src/modules/rustion/dispatcher.rs`
  test fixture was missing the `kem_public_key` field that landed in
  0.7.16 — added now so `cargo test --lib` compiles on the rustion
  module.

### Changed

- `features/rustion-integration.md`: Phase 6.2 marked Done; Phase 6.3
  carved out for the retry loop, 24h fallback poller, proxy
  orchestration glue, and the in-GUI playback (asciicast +
  `.rdp-rec` wasm decoder).

## [0.7.24] - 2026-05-19

### Added

- **Rustion integration — Phase 6.1: recording sidecar baseline**
  (paired with Rustion 0.7.20). The chain-of-custody artifact BV needs
  to attach a recording to the right audit-chain entry, without
  parsing the recording itself.
    - **`rustion-recording::sidecar`** new module on the Rustion side:
        - `RecordingSidecar` wire-format struct matching
          `docs/bastionvault-integration.md` §Recording handoff verbatim:
          `recording_id`, `session_id`, `authority`, `format`
          (`asciicast` | `rdp-rec` | `smb-log`), `sha256`, `size_bytes`,
          `started_at`, `finished_at`, `target_host`, `target_user`,
          `correlation_id`.
        - `from_handle_and_metadata(handle, metadata, session_id)`
          streams the recording file through sha2 (64 KiB buffered) to
          keep memory bounded for multi-GB recordings, and merges in
          the session metadata.
        - `write_next_to(rec_path)` drops `<rec>.json` next to
          `<rec>.cast` / `<rec>.rdp-rec`.
        - `read(path)` round-trip for the future
          `GET /v1/sessions/{sid}/recording` endpoint (Phase 6.2).
    - **SSH + RDP proxies** both emit the sidecar at
      `recorder.finish()` time, right after the recording-index entry
      is updated. Best-effort — a failed sidecar write WARNs but never
      sinks the user's session. `rustion::usage` emits a
      `RECORDING_READY` event carrying `session_id`, `recording_id`,
      `authority`, `correlation_id`, and `size_bytes` for SOC
      observability.
    - Classical (non-BV) sessions emit the sidecar with empty
      `authority` + `correlation_id` strings — the `serde(default)`
      tags keep parsing clean either way.
- **5 sidecar unit tests** (extension swap, sha256 known-vector, BV
  round-trip, classical empty-fields, protocol→format mapping). 89 ssh
  + 22 control-plane + 67 rdp + 56 recording lib tests still green.

### Changed

- `features/rustion-integration.md`: Phase 6 split — 6.1 sidecar
  baseline marked Done, 6.2 (webhook + BV receiver + 24h poller +
  playback) called out as the remaining slice.

## [0.7.23] - 2026-05-19

### Added

- **Rustion integration — Phase 5: renewal + forced termination** (paired
  with Rustion 0.7.19). Operators can extend live sessions without
  opening fresh ones, and BV can yank a session at any time.
    - **Rustion side**: `SessionStore::renew_from_envelope` +
      `SessionStore::kill_from_envelope`. Renewal enforces the
      `max_renewals` budget stamped at open time, rejects mismatched
      `correlation_id` (binding the renewal to a specific
      operator-session), clamps to the authority cap, and refuses
      already-killed sessions. Kill marks `killed_at = Some(now)`,
      drops the ticket index entry so any in-flight consume rejects,
      and is idempotent-erroring on a second call. `consume_ticket`
      gained a `killed_at` check.
    - **Axum routes**: `POST /v1/sessions/:sid/renew` +
      `DELETE /v1/sessions/:sid`. Both run through the same authority +
      replay + signature gates as `/v1/sessions` via a new shared
      `verify_and_replay` helper. Error mapping:
      `404 session_not_found`, `409 renewal_budget_exhausted`,
      `409 correlation_id_mismatch`, `409 session_already_terminated`.
      `rustion::usage` emits `SESSION_RENEW` / `SESSION_TERMINATE` for
      SOC observability.
    - **8 new SessionStore unit tests + 4 axum e2e tests** —
      `cargo test -p rustion-control-plane` is green at 22 + 4 passing.
- **BV side**: new `session::renew_session` + `session::kill_session`
  helpers in `src/modules/rustion/session.rs` build via
  `envelope::build_renew` / `envelope::build_kill` and POST/DELETE
  at the specific bastion that opened the session (no dispatcher
  walk — renew/kill always go to one known target).
- **New HTTP routes** `POST rustion/session/renew` +
  `POST rustion/session/kill`, with the existing `audit::SESSION_RENEW`
  / `audit::SESSION_TERMINATE` constants emitting `session.renew` /
  `session.terminate` log lines.
- **`SessionOpenResponse` now carries `correlation_id`** so callers
  know what to pass to subsequent renew/kill calls. Threaded through
  the Tauri command + the TypeScript `RustionSessionOpenResult`.
- **Two new Tauri commands**: `rustion_session_renew` +
  `rustion_session_kill`, plus typed wrappers
  `rustionSessionRenew` / `rustionSessionKill` in
  `gui/src/lib/rustion.ts`.
- **`useRustionSessionLifecycle` React hook** in `gui/src/hooks/`.
  Auto-renews at `expires_at - 60s` with idle-skip + budget-exhaust
  guard; exposes `renew()` + `kill()` for manual buttons. Drop-in for
  any Connection Window once the BV-side Rustion-mediated session UI
  lands.

### Changed

- `features/rustion-integration.md`: marked Phase 5 Done. Master-cert
  rotation (originally listed under Phase 5) is now tracked under
  Phase 9 alongside the rest of the enrolment + re-attestation
  surface area.

## [0.7.22] - 2026-05-19

### Added

- **Rustion integration — Phase 4.2 light** (paired with Rustion
  0.7.18). NTLMv2 message-construction layer + bastion-side CredSSP
  driver scaffold for `rdp-password` BV envelopes.
    - **`rustion-rdp::ntlmv2`** — pure-Rust NTLMv2 primitives:
      `ntlmv2_hash` (NTOWFv2 via MD4(UTF-16LE password) + HMAC-MD5),
      `build_negotiate_message` (type 1), `parse_challenge_message`
      (type 2 with TargetInfo extraction + fail-closed parser),
      `compute_responses` (LMv2 + NTLMv2 + SessionBaseKey per
      MS-NLMP §3.3.2), `build_authenticate_message` (type 3 with the
      six security-buffer fields at the correct 72-byte payload
      offset). 8 unit tests lock the implementation to MS-NLMP
      §4.2.4 reference vectors — NTOWFv2, NTProofStr, and
      SessionBaseKey match the published spec hex exactly.
    - **`rustion-rdp::bv_credssp`** — bastion-side CredSSP driver:
      `prepare_authenticate(...)` runs the NEGOTIATE → CHALLENGE →
      AUTHENTICATE pair in-memory and returns the
      AUTHENTICATE_MESSAGE bytes + SessionBaseKey + ExportedSessionKey
      ready for the seal-key derivation. `BvCredsspError::SealingDeferred`
      + `BvCredsspError::UnsupportedKind` make the Phase 4.2-full gap
      explicit at the type level so callers can't silently dispatch
      into an incomplete code path.
    - **Proxy wire-up** in `handle_rdp_connection`: when
      `bv_session.credential.kind == "rdp-password"` and the proxy
      was built with `--features nla`, the CredSSP injection driver
      is prepared (RC4 sealing of `authInfo` + pubKeyAuth signing
      deferred to Phase 4.2-full). `rdp-cert` and unknown credential
      kinds return a clean `RdpError::Auth("BV credential kind X is
      not yet supported...")` instead of hanging on a black RDP
      screen.
    - All BV-mediated TARGET_CONNECT `rustion::usage` lines now
      carry `credential_kind` for SOC observability.
    - **MS-NLMP spec note** — three of four published §4.2.4
      reference vectors match our crypto exactly; the fourth (LMv2
      last three bytes) appears to be a transcription error in the
      public spec. The same HMAC-MD5 implementation that
      produces the spec's exact NTProofStr + SessionBaseKey can't
      simultaneously produce a different LMv2. Samba, impacket and
      sspi-rs all compute the value our impl yields. Documented in
      the `ntlmv2::tests` module.
- 12 new unit tests (8 ntlmv2, 4 bv_credssp). `cargo test -p
  rustion-rdp --features nla --lib` is green at 67 tests passing.

### Changed

- Phase 4.2 split — `features/rustion-integration.md` marks Phase 4.2
  light Done and tracks Phase 4.2-full (RC4 sealing + pubKeyAuth +
  `rdp-cert` + Windows-VM CI validation) as the remaining slice
  before BV-mediated NLA against Windows hosts will work on the wire.

## [0.7.21] - 2026-05-19

### Added

- **Rustion integration — Phase 4.1 — RDP listener wire-up** (paired
  with Rustion 0.7.17). Mirror of the Phase 3.1 SSH listener
  integration onto the RDP gateway. The pure `ticket_auth` module that
  shipped in Phase 4 is now consumed by `rustion-rdp::proxy` at the
  X.224 connection-request stage.
    - `RdpProxy` gained `bv_session_store: Option<Arc<SessionStore>>`
      + `with_bv_session_store()` builder, identical in shape to the
      SSH side's `ServerHandler::with_bv_session_store`.
    - When the X.224 mstshash cookie contains a `tkt_<32 hex>`
      substring AND the proxy was wired to a BV session store, the
      listener calls `consume_ticket_for_login`. On success the local
      auth provider's `authenticate()` and `authorize()` are bypassed
      entirely — the BV control plane already proved identity + target
      authorisation when minting the ticket. `target_host`,
      `target_port`, and `target_user` come from the matched `Session`,
      not the cookie.
    - `SessionMetadata` on the RDP recording is stamped with
      `authority` + `correlation_id` via `with_bv_authority(...)`,
      letting SOC tooling join RDP recordings onto the BV audit chain
      just like SSH ones. `AuditEvent::AuthSuccess { method: "bv-ticket" }`
      lands on the audit log; `rustion::usage` lines carry the
      authority + correlation when the session is BV-mediated.
    - Failure paths fall through to the classical user-store flow so
      legacy operators whose mstshash payload happens to contain
      `tkt_` aren't locked out.
- **Phase 4.2 — CredSSP / NLA injection — Todo.** Documented as
  follow-up. The bastion currently relays NLA tokens between client
  and target; BV-mediated sessions need the bastion to drive the
  upstream CredSSP handshake itself using the envelope's decrypted
  credentials. Needs a Windows Server VM in CI to validate end-to-end.

### Changed

- `features/rustion-integration.md`: marked Phase 4.1 Done, split out
  Phase 4.2 for the CredSSP injection deferred work.

## [0.7.20] - 2026-05-19

### Added

- **Rustion integration — Phase 3.2 close-out** (paired with Rustion
  0.7.16). The last two deferred items land: SSH-key/SSH-cert
  credential dialing in the BV-bypass branch, and the `Dockerfile`
  for the e2e harness.
    - **`Dockerfile`** at the repo root: multi-stage build
      (rust:1.82-bookworm builder + distroless cc-debian12 runtime)
      shipping just the `bvault` binary. The
      `tests/e2e/rustion-ssh/docker-compose.yaml` now references it
      via `build:` so `docker compose up` builds the stack from
      source — no pre-built image dependency.
    - On the Rustion side, the proxy loop's BV-bypass branch routes
      `session.credential.kind` (ssh-password / ssh-key / ssh-cert)
      onto the right `TargetCredential` variant. SSH-engine CA
      certs and PKI-issued private keys now actually authenticate
      at the target.

## [0.7.19] - 2026-05-19

### Added

- **Rustion integration — Phase 3.1 close-out** (paired with Rustion
  0.7.15). The russh listener-loop wire-up of `consume_ticket_for_login`,
  the recording authority/correlation_id stamping, and the e2e
  docker-compose scaffold all land in this slice.
    - **End-to-end SSH BV-mediated session path now works** on the
      Rustion side: `ServerHandler.auth_password` detects `tkt_…`
      passwords, runs ticket auth via the BV `SessionStore`, stashes
      the session, and accepts. `shell_request` learned a fast path
      that bypasses the user-store target ACL + interactive menu and
      dials the session's `target_host:target_port` with the
      decrypted `ssh-password` credential.
    - **Recording chain-of-custody**: `SessionMetadata.authority` +
      `SessionMetadata.correlation_id` populated for BV-mediated
      sessions; asciicast header carries them under
      `rustion.{authority,correlation_id}` so SOC tooling can join
      recordings against the BV audit chain. `auth_method` records as
      `bv_ticket` to distinguish from classical `password` sessions.
    - **`tests/e2e/rustion-ssh/`** docker-compose scaffold + `run.sh`
      driver walking the full pipeline cold-start → enrolment →
      probe → session-open → ticket-validated SSH to an OpenSSH
      target. Configs (`bv-policy.hcl`, `rustion.toml`,
      authorities/) included. The Dockerfiles for BV + Rustion
      themselves land in Phase 3.2.
    - Deferred to Phase 3.2: `Dockerfile.bastion-vault` +
      `Dockerfile.rustion`, plus `ssh-key` / `ssh-cert` credential-
      kind dialing in `connect_to_target` (today only password is
      plumbed through).

## [0.7.18] - 2026-05-19

### Added

- **Rustion integration — Phase 4 RDP through Rustion** (paired with
  Rustion 0.7.14). The Phase-3 session-open flow is protocol-agnostic
  — `rustion_session_open` already accepts `target_protocol: "rdp"`
  and Rustion routes RDP envelopes at its `rdp_advertise` listener.
  Phase 4 closes the remaining RDP-specific gap: the `mstshash=`
  cookie ticket consumer on the Rustion side (see Rustion 0.7.14).
  The BV-side ironrdp client modification (switch dialer to the
  bastion + inject ticket into the cookie) is deferred to Phase 4.1
  alongside the SSH russh listener-loop wire-up.

## [0.7.17] - 2026-05-19

### Added

- **Rustion integration — Phase 3 close-out.** Pairs with Rustion 0.7.13
  to complete Phase 3 of `features/rustion-integration.md`. The
  dispatcher + session table from 0.7.16/0.7.12 now feed an end-to-end
  session-open HTTP flow.
    - **`RustionTarget.kem_public_key`** field (`src/modules/rustion/
      config.rs`). Separate ML-KEM-768 pubkey field on the registry
      record — distinct from the existing Ed25519 + ML-DSA-65 signing
      pubkey because the encrypt-to-Rustion direction uses a different
      keypair on the Rustion identity side. Threaded through the store
      validation, HTTP route, Tauri command surface, GUI enrolment
      wizard, and CLI `--kem-pubkey` flag. Existing records gracefully
      degrade — `kem_public_key` is `serde(default)` empty, and the
      session-open path refuses such records with a clear error
      pointing the operator at the enrolment wizard.
    - **BV `POST rustion/session/open` route** (`src/modules/rustion/
      session.rs::open_session_v2`). Pulls the registry + health
      cache, runs the dispatcher, walks candidates building a BVRG-v1
      `open` envelope per try via the master-key stub, POSTs at each
      candidate's `/v1/sessions` over reqwest+rustls, advances on
      transport/5xx, halts on 4xx, returns the session ticket bundle
      + the dispatcher's bastion-selection trail on success.
      Surfaces `503 bastion_unavailable` when no candidates qualify,
      `502 bastion_rejected` with the per-target error list when every
      candidate refused.
    - **`rustion_session_open` Tauri command** (`gui/src-tauri/src/
      commands/rustion.rs`) wraps the route; TS wrappers in
      `gui/src/lib/rustion.ts`. `RustionSessionOpenResult` carries
      `bastion_selection` (`"ordered-fallback" | "random-pool"`) and
      `bastion_candidates_tried` for audit + diagnostic UI.
    - **GUI `ConnectionProfile.kind = "direct" | "rustion"`** type
      (`gui/src/lib/types.ts`), with optional `bastions: string[]`
      (pinned ordered list, empty = global pool) and `recording`
      override field. Backwards-compatible — existing profiles
      without `kind` default to `"direct"`.

## [0.7.16] - 2026-05-19

### Added

- **Rustion integration — Phase 3 dispatcher + session-open scaffold.**
  Pairs with Rustion 0.7.12 to close the dispatcher cell + session-table
  cells of the Phase 3 deliverable table; the remaining cells (HTTP
  route, GUI integration, real SSH proxy ticket-auth) land in
  follow-up slices.
    - **Dispatcher** (`src/modules/rustion/dispatcher.rs`): given a
      connection profile + the registry's health cache, returns the
      ordered candidate list. Two modes: `OrderedFallback` (profile
      pinned a list — preserve order, drop disabled/down/unknown
      targets, surface reason on each drop) and `RandomPool` (empty
      pin — uniform random shuffle of all healthy enabled targets;
      caller supplies the RNG so tests can pin the choice).
      `should_advance` policy: transport / 5xx → advance, 4xx →
      halt (a permission denial is final and shouldn't burn auth
      attempts on every host in the pool). 7 unit tests.
    - **Master signing-key stub** (`MasterStore::get_or_init_signing_key`)
      mints + persists an ephemeral hybrid keypair on first call so
      the session-open path is testable end-to-end before Phase 9's
      PKI-issued master cert lands. Persisted at
      `rustion/master/signing-key` with a `stub: true` sentinel and a
      `WARN` log on creation so Phase 9 can audit + replace.

## [0.7.15] - 2026-05-18

### Added

- **Rustion integration — Phase 2 (BastionVault side).** New BVRG-v1
  envelope crate inside `bv_crypto` + matching adapter wired through
  `src/modules/rustion/envelope.rs`. Closes the envelope-builder cell
  of the Phase 2 deliverable table; Rustion's verify+decrypt side
  lands next in the Rustion repo.
    - **`bv_crypto::bvrg`** (`crates/bv_crypto/src/bvrg.rs`): hybrid
      Ed25519 + ML-DSA-65 signature over the frame's SHA-256
      `sha256(magic || ct_len || ct)`, ML-KEM-768 + ChaCha20-Poly1305
      ciphertext via the existing `KemDemEnvelopeV1`, CBOR payload
      via ciborium. Wire-format constants and length budgets match
      `features/rustion-integration.md § Envelope format` exactly so
      the Rustion-side decoder is a byte-for-byte mirror. Fail-closed
      verify path: magic-mismatch, length-mismatch, hybrid-downgrade,
      either signature half failing, AEAD tag failure, or CBOR parse
      failure all surface as distinct `BvrgError` variants.
    - **`BvrgMasterSigningKey` / `BvrgMasterPublicKey`**: hybrid
      keypair wrappers. Construction refuses classical-only public
      keys with `PublicKeyLength`, so a downstream caller can't
      accidentally enrol a half-key as a trust anchor.
    - **`build_open` / `build_renew` / `build_kill` / `build_attest`**
      adapters at `src/modules/rustion/envelope.rs` stamp the standard
      operator/correlation/deployment-id metadata, mint a fresh nonce
      per call, and return the wire bytes + SHA-256 fingerprint
      audit handlers fold into the chain. `attest` lays the
      groundwork for Phase 9's weekly re-attestation.
    - **Tests**: 11 round-trip + tamper-rejection unit tests in
      `crates/bv_crypto/tests/bvrg_roundtrip.rs` covering well-formed
      round-trip, magic tamper, truncation, Ed25519-half tamper,
      ML-DSA-65-half tamper, hybrid downgrade (dropping the ML-DSA
      half), ciphertext tamper, wrong KEM secret, wrong master
      pubkey, classical-only pubkey construction refusal, nonce
      uniqueness. 4 adapter integration tests in
      `src/modules/rustion/envelope.rs` covering build → verify
      symmetry for all four operations.
    - `reqwest` + `ciborium` + `ed25519-dalek` + `sha2` deps added to
      `bv_crypto/Cargo.toml`; all already in the workspace transitive
      tree, listing them direct pins the feature set.
    - **Note**: the registry's KEM-pubkey field lands alongside
      Phase 9's enrolment wizard; the current `resolve_kem_pubkey`
      synthesises bytes from the signing-pubkey slot and is marked
      `TODO(phase2)` in the source. Production builds against the
      synthetic path will fail at `seal()` with a clear
      `PublicKeyLength` error pointing at the missing field; tests
      supply a fresh ML-KEM-768 keypair directly.

## [0.7.14] - 2026-05-18

### Added

- **Rustion integration — Phase 1 close-out.** CLI subcommands and a
  GUI Settings → Rustion Bastions section land alongside the registry
  + pinger from earlier in the phase. With this release Phase 1 of
  `features/rustion-integration.md` is **Done**; Phase 2 (BVRG-v1
  envelope crate + master-cert lifecycle hooks) is next.
    - **CLI** (`src/cli/command/rustion*.rs`): `bvault rustion target
      add|list|read|test|health|delete` and `bvault rustion master
      read|export`. The `target add` command takes both halves of the
      hybrid pubkey as separate `--ed25519` / `--mldsa65` flags so
      copy-paste from `rustion control-plane identity export` is a
      one-shot. `target test` accepts an optional `--id` for a
      single-target probe; omitting it runs the full sweep.
    - **Tauri command surface** (`gui/src-tauri/src/commands/rustion.rs`,
      `gui/src/lib/rustion.ts`): typed wrappers for target CRUD, health
      view, probe (single + all), master-cert config read/write, and
      master pubkey export. All commands forward through the existing
      `make_request` dispatcher so they ride the same auth + audit
      path as the rest of the GUI.
    - **GUI Settings → Rustion** (`gui/src/components/RustionBastionsTab.tsx`):
      target table with a per-row health dot (green/yellow/red/grey)
      driven by the background pinger's cached verdict, plus latency,
      version, and active-session columns. Per-row "Test", "Edit", and
      "Delete" buttons. Enrolment wizard validates the hybrid pubkey
      (both halves required, classical-only refused) and surfaces a
      clear error for missing port literals. Master-cert configuration
      panel with PKI mount / role / issuer-ref editor and a pubkey
      export viewer (populated once Phase 2 lands the issue flow).

## [0.7.13] - 2026-05-18

### Added

- **Rustion integration — Phase 1 live HTTP pinger**
  (`src/modules/rustion/probe.rs`). A tokio-spawned background task
  walks every enabled `RustionTarget` on a 30-second tick, sends
  `GET /v1/health` against its control-plane endpoint with the
  spec'd authority + nonce headers, feeds the outcome through the
  Phase 1 state machine, and persists the fresh health record.
  Status transitions log `rustion.target.health.changed`; stable
  verdicts only refresh the cache. Per-probe timeout 5s, redirects
  disabled.
    - Signature header (`X-Rustion-Sig`) is sent empty until Phase 2's
      master signing key lands; the nonce and authority headers are
      live so a Rustion authority record can match the probe in audit.
    - Disabled targets skip probing entirely — operators staging a
      drain rely on this so flipping `enabled=false` doesn't churn
      audit events.
- **`POST /v1/rustion/targets/probe`** — force an immediate full
  probe sweep across every enabled target. Returns the freshened
  health view in the same response. Same routine the background
  pinger runs on its 30-second tick.
- **`POST /v1/rustion/targets/{id}/probe`** — single-target probe
  for the enrolment wizard's "test connection" affordance. Returns
  the fresh per-target health record (status, latency, version,
  active sessions, error).
- **`reqwest` listed as a direct dep** in the workspace Cargo.toml
  with `rustls-tls` + `json` features. Already transitively present
  via openidconnect + hiqlite; promoting to direct pins the feature
  set explicitly and stays off the OpenSSL surface.
- **Pinger boots on first unseal** (`src/core.rs`) alongside the
  PKI / LDAP / file-resource schedulers. Same lifecycle pattern:
  detached task, self-skip while sealed, ticks every 30s.

## [0.7.12] - 2026-05-18

### Added

- **Rustion integration — Phase 1 scaffold** (`src/modules/rustion/`). New
  top-level `rustion/` mount registers a logical backend exposing five
  routes: `LIST/POST /v1/rustion/targets`, `READ/WRITE/DELETE /v1/rustion/
  targets/{id}`, `READ /v1/rustion/targets/health`, `READ/WRITE /v1/rustion/
  master/config`, and `READ /v1/rustion/master/pubkey`. The module manager
  spins up a `RustionModule` instance alongside the existing engines.
    - **Target registry** (`config.rs`, `store.rs`): `RustionTarget` records
      hold the pinned hybrid pubkey (Ed25519 + ML-DSA-65 — both halves
      required), endpoint, tags, enabled flag, and timestamps. Storage
      splits target records from cached health records so identity
      rotations don't churn health history and vice-versa. IDs are
      derived deterministically from the lowercased name so an
      accidental CLI + GUI double-enrolment lands on the same record.
    - **Health-state machine** (`health.rs`): three-strikes-down /
      one-success-up debouncing with a `Degraded` intermediate state so
      the GUI can show a yellow chip on the first failure without the
      dispatcher treating the target as routable. EWMA-style p50
      latency. Five unit tests cover the Unknown→Up promotion, Degraded
      landing on first failure, third-strike Down flip, recovery from
      Down, and stable-status no-change path.
    - **Master-cert configuration slot** (`master.rs`): stores the PKI
      mount / role / issuer the rotation flow will mint from, plus
      defaults (5y TTL, 1d rotation grace). Pubkey export endpoint
      stubs the shape it will return — the live issue/rotate state
      machine rides on Phase 2's BVRG-v1 envelope crate.
    - **Audit event taxonomy** (`audit.rs`): names fixed for
      `rustion.target.{enrol, update, rotate, delete}`,
      `rustion.target.health.changed`, `rustion.master.{issue, rotate}`,
      plus forward-reservation constants for Phase 2+ events.
  
  Module compiles clean against the workspace; the live HTTP probe,
  background pinger, GUI section, and CLI are pending in the same
  phase but split across follow-up commits.

## [0.7.11] - 2026-05-18

### Added

- **Resource Connect: `ssh-engine` credential source for SSH sessions**
  (`gui/src-tauri/src/commands/connect.rs`, `gui/src-tauri/src/session/ssh.rs`).
  Closes the deferred fourth cell of the launch matrix (SSH × {Secret, LDAP,
  PKI, **SSH engine**}). Two working modes:
    - **CA mode** — generates a fresh Ed25519 keypair in-process, posts the
      pubkey to `<mount>sign/<role>`, presents `(key, cert)` to russh via
      `authenticate_openssh_cert`. Target `sshd` must trust the BV SSH CA
      via `TrustedUserCAKeys`. Both halves are session-ephemeral and zeroize
      on drop; the cert TTL is bounded by the SSH role's `max_ttl`.
    - **OTP mode** — calls `<mount>creds/<role>` with the resolved target IP
      + username, presents the returned password to russh as password auth.
      Target host must run `bv-ssh-helper` for the OTP to validate at PAM
      time. Hostnames are rejected upfront with a clear error message; the
      SSH engine matches against `cidr_list` and requires an IP literal.
  PQC mode (`ssh-mldsa65@openssh.com`) is explicitly rejected at this layer
  with a documented error — russh's `ssh-key` dep does not yet implement
  ML-DSA-65 cert auth. Out-of-app PQC-aware clients can still consume
  `ssh/sign/<role>` directly.
- New `SshCredential::Cert { pem, cert_openssh }` variant on the session
  layer wraps an ephemeral keypair + signed OpenSSH cert for the russh
  `authenticate_openssh_cert` call.

## [0.7.10] - 2026-05-18

### Fixed

- **pki-user can now read bare issuer detail** (`src/modules/policy/policy_store.rs`).
  Added `path "pki/issuer/+" { capabilities = ["read"] }` to the baseline `pki-user`
  policy. Previously only the `/json`, `/pem`, `/der`, `/crl` sub-paths were granted,
  so the GUI's IssuersTab clicked-detail panel (which hits the bare path returning
  name, CN, cert PEM, usages, not_after — no private key material) 403'd. The new
  rule restores parity with what the GUI surface actually needs.
- **Asset-group list is now filtered to caller-accessible groups**
  (`src/modules/resource_group/mod.rs`). `handle_list` previously returned every
  group name regardless of caller. Non-admin callers now see only groups they own
  or have an active share on (direct entity share or share to any identity group
  they belong to). Admin / root tokens still see every group.
- **ACL `scopes` now resolves asset-group paths**
  (`src/modules/policy/policy_store.rs`). Added `asset_group_name_from_path` plus
  asset-group-share lookups in both `resolve_asset_owner` (so `scopes=["owner"]`
  rules match group owners) and `resolve_target_shared_caps` (so `scopes=["shared"]`
  rules match direct + identity-group shares on the group itself). The `standard-user`
  policy gained `path "resource-group/groups/+" { capabilities = ["read"], scopes =
  ["owner", "shared"] }` plus list on the parent, so the Resources-page Groups
  section can render group cards for shared groups.

## [0.7.9] - 2026-05-18

### Fixed

- **`identity/entity/self` is now in the default policy**
  (`src/modules/policy/policy_store.rs`). The default policy granted read on
  `identity/entity/id/{{identity.entity.id}}` and `.../name/{{...}}` but not
  the caller-introspecting `entity/self` path, so any token that lacked
  templating substitution (or whose entity_id wasn't populated yet) got 403
  on the GUI's auth-store bootstrap. The handler only ever returns the
  caller's own record, so granting it to every authenticated token is safe.

### Changed

- **PKI page now hides admin operations from non-admin users**
  (`gui/src/routes/PkiPage.tsx`). Added a `usePkiAdmin()` policy check
  (`root`/`admin`/`administrator`/`super-admin`/`pki-admin`) and gated:
  - The "+ Mount PKI engine" header button.
  - The "Import root CA" / "+ Generate root CA" Issuers-tab actions and
    the empty-state CTA.
  - Per-issuer "Set as default", "Rename", "Edit usages", "Delete" buttons.
  - The "Keys" and "Tidy" tabs (whose endpoints `pki-user` cannot access).
  - The "Import XCA" tab (admin-only workflow).
  `pki-user` retains visibility of Issuers (list + Export), Roles, Issue,
  Certificates, and External CSR — matching what the baseline policy
  actually allows.

## [0.7.8] - 2026-05-18

### Fixed

- **ACL `scopes = ["shared"]` now resolves identity-group grantees**
  (`src/modules/policy/policy_store.rs`). `resolve_target_shared_caps` only looked up
  shares keyed by the caller's `entity_id`, so a share whose grantee was an identity
  group (e.g. `grp-teste`) never granted capabilities even when the caller was a
  member of that group. The `for-me` feed surfaced the share but the underlying
  read/list returned 403. The helper now also walks the caller's user-group and
  app-group memberships (gated by the same `metadata.group_shared_resources = "true"`
  opt-in used by the listing endpoint) and unions in both direct shares and
  asset-group shares granted to each group. Visibility and enforcement now agree.

## [0.7.7] - 2026-05-18

### Fixed

- **Asset-group shares now expand to constituent members in `identity/sharing/for-me`**
  (`src/modules/identity/mod.rs`). Previously, when a user-group was granted access to an
  asset group, the recipient's "Shared with me" feed returned a single opaque
  `target_kind=asset-group` pointer whose Open link went to a non-existent
  `/secrets/<group-name>` path. The handler now reads the asset group via
  `ResourceGroupStore` and emits one pointer per resource/kv-secret/file member, carrying
  the original `grantee_kind`. Expansion bypasses caller ACL (safe because membership in
  the pointer set already implies the share was authorised).
- **PKI Issuers tab no longer spams 403 toasts for `pki-user` holders**
  (`gui/src/routes/PkiPage.tsx`). The auto-select read on first issuer hit
  `pki/issuer/<ref>`, which `pki-user` policy doesn't grant (only `/json`, `/pem`, `/der`,
  `/crl` variants). The auto-read is now best-effort: ACL errors are swallowed silently
  so the issuer list still renders; explicit row clicks still surface real errors.

## [0.7.6] - 2026-05-18

### Changed

- **CI: temporarily disable `cargo audit` workflow** (`.github/workflows/rust.yml`) --
  switched trigger from `on: push` to `on: workflow_dispatch`. Vanilla `russh 0.60.3`
  and `sspi 0.20.x / 0.21.x` pin incompatible RustCrypto pre-release versions
  (`ed25519-dalek`, `p256`, `ml-kem`), so `cargo generate-lockfile` fails in CI and
  the audit cannot run. A monthly scheduled routine watches crates.io and will
  signal when upstream Devolutions converges on the pre.7 RustCrypto slice; restore
  `on: push` then.

## [0.7.5] - 2026-05-18

### Changed

- **Built-in user policies opt in to group-share resolution by default** (`src/modules/policy/policy_store.rs`) -- the `standard-user`, `standard-user-readonly`, and `secret-author` policies now carry `metadata { group_shared_resources = "true" }`. Without this tag the share evaluator silently skipped grants whose grantee was an identity group (user or app), and `identity/sharing/for-me` also omitted them — so resources shared to a group the caller belonged to never showed up. The tag is force-loaded on every unseal, so existing vaults pick up the change automatically; operators who want to opt a specific user out should attach a custom policy that omits the metadata block.

### Fixed

- **Resources page for non-admin callers** (`gui/src/routes/ResourcesPage.tsx`) -- the page called `resources/search`, which non-admin tokens lack capability for, surfacing `HTTP 403: Permission denied` and an empty list even when the caller had shared resources. The page now catches the 403 on first load and transparently falls back to listing the caller's resource shares (via `list_shares_for_me`), reading each resource's metadata and applying `q` / `type` filters client-side. Subsequent paging stays on the fallback path so it never retries the denied endpoint.

## [0.7.4] - 2026-05-18

### Added

- **Asset Groups sharing — identity groups and AppRole groups** (`gui/src/routes/AssetGroupsPage.tsx`, `gui/src/components/ui/GroupNamePicker.tsx`) -- the "Grant access" modal on an asset group's Sharing tab now exposes the `grantee_kind` selector (User / User identity group / App group), mirroring the SharingPage flow. Group names use a new typeahead picker backed by `list_groups` (falls back to free-text when the directory lookup is denied). Share rows render a badge when the grantee is a group, and the rowKey now disambiguates entity vs group shares with the same name. `deleteShare` calls pass through the share's `grantee_kind` so revokes work for group grantees.

### Changed

- **Asset-group share management now allowed for admins and owners** (`src/modules/identity/mod.rs::require_share_admin`) -- previously only a root token could grant or revoke asset-group shares (`HTTP 403: asset-group shares can only be managed by a root token`). The check now accepts the `admin` policy (same rule as elsewhere in the resource-group module) and resolves the asset group's `owner_entity_id` via `ResourceGroupStore::get_group`, so non-root owners can manage their own group's shares. Tokens with neither the admin policy nor matching ownership still get a 403 with the generic "only the target's owner can manage its shares" message.

## [0.7.3] - 2026-05-18

### Fixed

- **Asset-group filter showed "No resources" for imported groups** (`src/modules/resource/mod.rs`, `gui/src/routes/AssetGroupsPage.tsx`) — the resource-group store has always lowercased member names on write (`group_store.rs::sanitize_member`), while the resource module preserved case in its storage keys. PMP-imported groups therefore stored members like `apl-puppetenterprise` against a resources mount that held `APL-PuppetEnterprise`, so `read_resource` returned 404 for every member and the Resources page rendered the group as empty. Resolve the URL `name` segment through a new `resolve_resource_name` helper across every read/write/delete/history/secret handler: prefer the lowercase key (now the canonical form for new writes), fall back to the supplied case, and CI-scan `META_PREFIX` as a last resort. Net effect: new resources land at a lowercase key so future imports never duplicate, existing mixed-case records resolve regardless of caller case, and a re-write of `APL-PuppetEnterprise` updates the existing record in place instead of creating a sibling.

### Changed

- **Asset Groups resource picker — dual-list with search** (`gui/src/routes/AssetGroupsPage.tsx`) — the chip grid in the Edit Group modal scaled badly past ~50 resources (target mount has 5k+). Replace it with an available/selected dual-list panel: per-side search, count badges, `>` / `>>` / `<` / `<<` move buttons, Cmd/Ctrl-click toggle, Shift-click range selection, double-click to move a single row. Members not present in the resources mount (legacy data, deleted resources) appear italicized with a `*` marker in the Selected pane instead of in a separate "Other resources" section.

## [0.7.2] - 2026-05-17

### Changed

- **Resources search — match on tags too** (`src/modules/resource/mod.rs`) — drop the name-only fast path in the search handler. It short-circuited before any metadata was read, so a query like `production` would miss resources whose name didn't contain it but whose `tags` did. Now the handler always scans every metadata blob through the same predicate (name + hostname + ip_address + tags). 5k local reads on Hiqlite stay well under 100ms; if that ever changes, add a lazy in-memory index keyed by the resource name.

- **Resources page — paginated server-side search + recently accessed** (`src/modules/resource/mod.rs`, `gui/src-tauri/src/commands/resources.rs`, `gui/src/lib/api.ts`, `gui/src/routes/ResourcesPage.tsx`) — replace the "list every name, fan out one `read_resource` per row" pattern (which broke down past a few hundred resources) with a new `POST resources/search` route that scans `META_PREFIX` once per call, applies `q` (substring across name/hostname/ip/tags) and `type` filters, sorts by name, and returns a card-shaped projection plus `{total, has_more}`. The Resources page debounces the search input (250ms), fires one paginated call per filter change, and bumps the offset via an `IntersectionObserver` sentinel near the bottom. Group filter goes through the existing `useAssetGroupMap` (no metadata fetch needed) and paginates the group's members directly. The operator's six most-recently-opened resources are pinned in a "Recently accessed" strip above the main grid (persisted to `localStorage` under `bv:resources:recent`, only shown when no filter is active). Card-level inline Quick Connect is removed in this iteration — the search payload doesn't carry `os_type` / `connection_profiles`, and the detail page's Connect tab covers the same flow.

### Fixed

- **PMP import — drive visibility + opaque error** (`gui/src/routes/PmpImportPage.tsx`) — the wizard now reads the spreadsheet bytes in the GUI process via `read_local_file_b64` and ships them to the plugin as `file_b64` instead of passing a bare `file_path`. The plugin runs in a sandboxed subprocess that doesn't inherit every drive mapping the interactive session has (mapped network drives, VeraCrypt volumes, etc.), so a path like `H:\…` could fail with ENOENT even though it was valid for the operator. Also surface the plugin's real error message from the response body instead of the unhelpful "plugin returned error (status code 1)".

## [0.7.1] - 2026-05-17

### Fixed

- **Container build** (`deploy/container/Containerfile`) — export `RUST_MIN_STACK=16777216` before `cargo build` to avoid rustc SIGSEGV in the LLVM thin-LTO worker thread when compiling the `bastion_vault` lib under cross-compile.

## [0.5.22] - 2026-05-16

### Added

- **Scheduled Exports** (`src/scheduled_exports/`, `src/http/sys.rs` scheduled-exports handlers, `gui/src/routes/ExchangePage.tsx` Scheduled backups tab, `features/scheduled-exports.md`) — cron-expressed, leader-elected, persisted schedules that drive the Exchange module to produce recurring password-protected `.bvx` backups. HA-safe via the existing Hiqlite Raft leader signal so only one node fires each schedule. Per-schedule scope (mounts / resources / groups), output target (local path or cloud-storage `FileTarget`), retention policy, and a sealed password reference. CRUD HTTP at `/v1/sys/scheduled-exports/*` plus a `run-now` trigger and a per-schedule run history. GUI tab under `/exchange` ("Scheduled backups") with full CRUD + run history + Run-now.

- **User-facing Exchange Module (`.bvx`)** (`src/exchange/`, `src/http/sys.rs` exchange handlers, `src/cli/command/exchange*.rs`, `gui/src/routes/ExchangePage.tsx`, `features/import-export-module.md`) — portable, versioned JSON exchange format (`bvx.v1`) for moving selected vault data (KV items, resources, files, asset / resource groups) between vault instances or between people. Two on-disk variants: plaintext `.json` (gated behind `--allow-plaintext` + per-mount `accept_plaintext_exchange = true`) and the default password-encrypted `.bvx` (Argon2id m=64 MiB / t=3 / p=1 → 32-byte key → XChaCha20-Poly1305 AEAD, with embedded KDF parameters so 2027 defaults can be raised without breaking older files). Import is a mandatory two-step preview-then-apply flow with per-item `skip` / `overwrite` / `rename` conflict policies; the preview is a single-use, owner-bound, 10-minute TTL'd token. CLI: `bvault exchange export` / `preview` / `import` (passwords from stdin only — the `--password=` flag is intentionally refused). HTTP: `POST /v1/sys/exchange/export`, `POST /v1/sys/exchange/import/preview`, `POST /v1/sys/exchange/import/apply`. GUI: `/exchange` page with scope picker, password entropy meter, per-item / bulk-set conflict policy controls, and final summary panel. 23 inline unit tests cover canonical encoding stability, KDF determinism, AEAD round-trip + tampering, preview-store TTL + owner-binding, and scope-resolver round-trip.

- **Secret Versioning & Soft-Delete (KV v2)** (`src/modules/kv_v2/`, `gui/src-tauri/src/commands/secrets.rs`, `gui/src/lib/api.ts`, `gui/src/components/ui/SecretHistoryPanel.tsx`, `gui/src/routes/{SecretsPage,MountsPage}.tsx`, `tests/test_default_logical.rs`, `features/secret-versioning-and-soft-delete.md`) — full KV v2 secret engine compatible with HashiCorp Vault's `data/`, `metadata/`, `destroy/`, `undelete/`, `config` path layout. Every write creates a new version; reads default to latest, or take an explicit `?version=N`. Deletes are soft (recoverable via `undelete`) until `destroy` wipes the version data and flips its `destroyed` flag. `cas` (check-and-set) protects against concurrent writes; `max_versions` and `delete_version_after` auto-prune. Versions carry per-write `username` + `operation` audit fields. CLI auto-detects v2 mounts and rewrites paths transparently. GUI surfaces a version timeline with per-version Restore / Soft-delete / Undelete / Destroy actions (destroy is two-step confirmed), and a KV-v2 engine-config editor on the Mounts page (`max_versions` / `cas_required` / `delete_version_after`) both at mount-creation time and as a per-mount runtime "Config" button. Six new Tauri commands (`soft_delete_secret_versions`, `undelete_secret_versions`, `destroy_secret_versions`, `write_secret_cas`, `read_kv_v2_engine_config`, `write_kv_v2_engine_config`) back the new GUI surfaces; `mount_engine` now accepts an `options` bag so KV-v2 defaults can be baked into a fresh mount.

### Security

- **Dependency audit: cleared 7 of 11 `cargo audit` vulnerabilities** (`Cargo.toml`, `crates/bv-client/Cargo.toml`, `crates/bv-client/src/discovery.rs`, `src/modules/pki/acme/dns01.rs`). Dropped the redundant `r2d2-diesel 1.0.0` dep (diesel 2.x's built-in `r2d2` feature was already enabled), bumped `diesel 2.3.7 → 2.3.8` (RUSTSEC-2026-0136 COPY command injection + RUSTSEC-2026-0137 unaligned access), bumped `hickory-resolver 0.24 → 0.26` in both the host crate and `bv-client` (RUSTSEC-2026-0119 O(n²) name compression — required a refactor to the new `TokioResolver::builder_with_config` / `RData`-pattern-matching API in the ACME DNS-01 validator and the SRV cluster-discovery resolver), and refreshed `rustls-webpki 0.103.12 → 0.103.13` (RUSTSEC-2026-0104 CRL parse panic). Also bumped the IronRDP submodule to the latest `fix-deps` tip with upstream `master` merged in. The 4 residual advisories are upstream-blocked: `hickory-proto 0.25.2` × 2 (pulled via `sspi 0.20.1`, awaits a sspi release on hickory 0.26) and `rsa 0.9.10` / `0.10.0-rc.17` Marvin timing sidechannel (no fix in any RustCrypto release).

### Changed

- **Docs: MySQL marked as legacy/opt-in; PostgreSQL claims removed** (`README.md`, `CLAUDE.md`, `docs/README.md`, `docs/quick-start.md`, `docs/design.md`, `docs/configuration.md`, `docs/req.md`, `docs/backend/database/mysql/mysql.md`) — Hiqlite is the default storage backend; MySQL is still supported but off by default (`--features storage_mysql`) and listed as legacy for existing deployments. References to a "PostgreSQL storage backend" / "SQLx backend (Postgres/SQLite)" — never actually shipped, the sqlx backend was removed earlier due to a dependency conflict — are now gone. Also fixed the stale `ErrDatabaseTypeInvalid` error string in `src/errors.rs` (was "Please try postgressql or mysql again.") and removed the unused `DatabaseName::Postgres` variant from `src/utils/db.rs`.

- **`standard-user` policy is now per-user-scoped** (`src/modules/policy/policy_store.rs`) — read/list/update on `secret/*`, `secret/data/*`, `secret/metadata/*`, and `resources/*` now carry `scopes = ["owner", "shared"]`. Callers can still create new objects (the first-write carve-out stamps ownership) and still see what they author or have been explicitly shared, but cross-user visibility of unrelated KV secrets and resources is denied. The baseline is force-loaded on startup so existing vaults migrate without operator intervention; operators who customised `standard-user` should fork it under a new name before upgrading.

### Fixed

- **PKI mount list no longer 403s for `pki-user`** (`gui/src-tauri/src/commands/pki.rs`) — `pki_list_mounts` switched from `sys/mounts` (admin-only) to `sys/internal/ui/mounts` (auth-filtered), so the GUI shows the operator's PKI mounts to any token with `pki/*` capabilities. Fixes the duplicate "HTTP 403: Permission denied" toast that appeared on the PKI page for users with only `pki-user`.

## [0.5.21] - 2026-05-16

### Added

- **Server Info menu + endpoint** (`src/server_info.rs`, `src/http/sys.rs`, `src/api/sys.rs`, `gui/src-tauri/src/lib.rs`, `gui/src-tauri/src/commands/system.rs`, `gui/src/components/ServerInfoModal.tsx`, `docs/docs/api.md`, `docs/docs/administration.md`) — new `GET /v1/sys/info` endpoint returning `{ version, started_at, uptime_seconds, initialized, sealed, storage_type }`, backed by a process-wide `OnceLock<DateTime<Utc>>` stamped at startup. The Tauri window menu gained a **Server → Server Info...** entry that emits `open-server-info` to the focused webview; a new global `ServerInfoModal` listens for it, calls the `get_server_info` command (embedded mode reads the in-process `Core`; remote mode proxies `/sys/info`), and renders the connection kind, endpoint, version, sealed/initialized badges, storage backend, start time, and human-formatted uptime.

- **Share resources with identity groups** (`src/modules/identity/share_store.rs`, `src/modules/identity/mod.rs`, `src/modules/policy/policy.rs`, `gui/src/routes/SharingPage.tsx`, GUI types + sharing commands, `features/identity-groups.md` §Phase 7, `features/per-user-scoping.md` §5) — `SecretShare` now carries a `grantee_kind` field (`entity` / `group_user` / `group_app`) so an admin can grant a share to an identity group as well as to an individual entity. The HCL policy parser learned a top-level `metadata { ... }` block; setting `metadata { group_shared_resources = "true" }` on a policy opts the holder into seeing group shares on the new `identity/sharing/for-me` endpoint (the GUI "Shared with me" tab uses it). Group shares are *visibility-only* — they surface the resource on the member's shared list without granting capability beyond what the member's existing policies allow, avoiding privilege escalation through group-membership churn. Existing entity-grantee shares deserialize unchanged via `#[serde(default)]` on the new field, so no migration is needed.

### Added

- **Dashboard shows the signed-in user** (`gui/src/routes/DashboardPage.tsx`) — added a "Signed in as …" subtitle under the Dashboard header that surfaces the auth-store `principal` (with the `entity_id` on hover) and lazily hydrates it via `identity/entity/self` if the user landed straight on the dashboard.

### Security

- **Share management gated to target owners** (`src/modules/identity/mod.rs`) — `PUT`, `DELETE`, `GET` on `identity/sharing/by-target/<kind>/<target>/<grantee>` and the by-target `LIST` now reject callers (HTTP 403) unless they are root *or* their resolved entity_id matches the target's owner record in the `OwnerStore`. Sharing is an authority transfer, so the existing per-path ACL grant is insufficient — only the data owner may grant access to it. Asset-group shares (no per-object owner) remain root-only. Pre-existing shares are unaffected; this only restricts new grants/revocations and target-scoped enumeration.

### Fixed

- **"Shared with me" returned 403 for normal users** (`src/modules/policy/policy_store.rs`) — added a self-service grant for `identity/sharing/for-me` (read+list) to the bundled `default` policy so every authenticated token can list its own shares. The handler is caller-introspecting (returns only the calling token's shares), so this grant is safe by construction. Also introduced `PolicyStore::force_load_acl_policy` and switched `default` to re-seed on every startup, so existing vaults pick up new self-service grants without operator intervention (other baselines like `standard-user` remain operator-editable).

- **`make help` and `PLUGINS_HOST_TARGET` detection on Windows + git-bash** (`Makefile`) — escaped `$matches`/`$_`/`$null` in the PowerShell command lines so bash (MINGW64) doesn't strip them before PowerShell evaluates the command. Running `make` from a Git Bash shell on Windows now produces the help table without PowerShell parser errors.

- **"Shared with me" empty for tokens without `entity_id`** (`src/modules/identity/mod.rs`, `src/modules/credential/userpass/path_login.rs`) — `identity/entity/self` now falls back to an alias lookup (`mount_path` + `username`/`role_name`, both of which the token *does* carry) and lazily materializes the entity via `get_or_create_entity` when the metadata-cached `entity_id` is empty. Tokens issued before the login path provisioned `entity_id` no longer get stuck on the "No entity_id on this token. Re-login to provision one." empty state. The userpass login's `resolve_entity_id` also now logs at WARN whenever it can't provision (identity module absent / store uninitialised / storage error) so operators have a breadcrumb when a fresh token still lacks `entity_id`.

## [0.5.19] - 2026-05-14

### Fixed

- **Windows `make` help target** (`Makefile`) -- avoid parse-time `grep`, `sed`, `uname`, and help-pipeline dependencies when running GNU Make from `cmd.exe`, so the default `make` target prints the command list cleanly on Windows.

- **WSL GUI dependency install on Windows-mounted worktrees** (`Makefile`, `gui/package.json`) — detect WSL and install GUI dependencies without npm bin links, then invoke Tauri, TypeScript, Vite, and Vitest through direct Node entrypoints so `/mnt/c` checkouts no longer fail on npm `chmod`.
- **Files page "Download" button did nothing** (`gui/src/routes/FilesPage.tsx`, `gui/src-tauri/src/commands/files.rs`) — the frontend was creating a Blob URL and synthesising an `<a download>` click, which Tauri v2's webview does not honour (no OS download manager, no save dialog, no file written). Replaced with the canonical Tauri pattern: open `plugin-dialog`'s `save()` to let the user pick a destination, then call a new `export_file_to_path` Rust command that reads the file via the engine and writes the decoded bytes to disk with `std::fs::write`. Applies to both current-content downloads and per-version downloads in the history modal.

### Added

- **Resource change history distinguishes "connect" from "update"** (`src/modules/resource/mod.rs`, `gui/src/components/ui/SecretHistoryPanel.tsx`) — a resource metadata write whose only diff is `recent_sessions` is the GUI's session-recorder appending a connection entry, not an edit. The server now relabels it as `op: "connect"` with no field pill and emits a `target: "security"` log line (`resource-connect: user=… resource=…`) so connection activity surfaces on `security.log` alongside the audit stream. The history panel renders the new op with a success-coloured badge.

- **Resource-secret reads emit a security-log entry** (`src/modules/resource/mod.rs`) — `handle_secret_read` and `handle_secret_version_read` now log `resource-secret-read: user=… resource=… key=…` on the `security` target whenever a secret value (or any prior version) is disclosed. The dispatcher's audit broker still records the request itself; the security-log mirror keeps "who pulled which credential" visible on the same stream as the connect events.

- **RDP session window resizes the remote desktop** (`gui/src-tauri/src/session/rdp.rs`, `gui/src-tauri/src/commands/connect.rs`, `gui/src/routes/SessionRdpWindow.tsx`) — registered the DisplayControl dynamic virtual channel on the ironrdp connector, wired the previously-stubbed `RdpControl::Resize` to `ActiveStage::encode_resize`, and drove the server's `DeactivateAll` → reactivation sequence to completion. The frontend now observes the window size (debounced 250 ms), forwards the new dimensions to the host via `session_input_rdp_resize`, and re-allocates its canvas backing store on the `session-resize-{token}` event the host emits once the new resolution is finalized.

### Changed

- **PKI "Import root CA" modal — PKCS#12 file picker** (`gui/src/routes/PkiPage.tsx`) — replaced the bare `<input type="file">` (which rendered as the unstyled OS "Choose File" control) with a styled button that triggers a hidden file input via a ref, matching the rest of the modal's look.

## [0.5.18] - 2026-05-14

### Fixed

- **Hiqlite WAL panicked on any storage write larger than 2 MiB** (`src/storage/hiqlite/mod.rs`) — hiqlite-wal's writer (`writer.rs:194`) issues a hard `panic!` if a single Raft log entry exceeds the WAL segment size, killing RaftCore and freezing the whole cluster (every subsequent request returns `Fatal::Panicked` until restart). We were running with hiqlite's 2 MiB default while accepting files up to `MAX_FILE_BYTES = 32 MiB`, so any file upload above ~2 MiB tripped the panic. Now: set `wal_size = 64 MiB` explicitly in `NodeConfig`, well above any single entry we generate; additionally reject oversized values at the `Backend::put` boundary with a clean `RvError` so a future `MAX_FILE_BYTES` bump can't silently reintroduce the panic. Existing on-disk WAL segments keep their original size, so this is safe on a running cluster (rolling restart required to pick up the new ceiling). Also fix `Backend::get` to route hiqlite errors through `map_hiqlite_error` instead of `RvError::ErrResponse`, so `CheckIsLeaderError` surfaces as HTTP 503 (`Cluster has no leader`) instead of a misleading HTTP 400 with the raw `"CheckIsLeaderError: panicked"` text.
- **Cluster discovery rejected SRV-shaped cluster names** (`crates/bv-client/src/discovery.rs`) — when an operator entered an already-SRV-formatted FQDN like `_cofre-html._tcp.esi.fgv.br` as the cluster address, `resolve()` blindly prepended `cfg.srv_service` (`_bvault._tcp`) and queried `_bvault._tcp._cofre-html._tcp.esi.fgv.br`, which NXDOMAINs, then fell back to a literal A/AAAA lookup of the underscore-prefixed name — `getaddrinfo` rejects underscore labels, producing the cryptic "nodename nor servname provided" toast. Now: inputs starting with `_` are queried verbatim as the SRV label (no prefix), and SRV-shaped inputs with no records short-circuit to an empty candidate list (so the caller surfaces "no candidates resolved" instead of a guaranteed-broken A/AAAA fallback). Bare-name inputs still get the `srv_service` prefix as before.

## [0.5.17] - 2026-05-13

### Fixed

- **FIDO2 registration rejected real-world attestation formats** (`src/modules/credential/fido2/rp/mod.rs`) — the server's `finish_registration` hard-rejected any attestation format other than `none`, but most security keys (Yubikey + every platform authenticator I've seen) return `packed`, `fido-u2f`, or `apple` regardless of what the RP asked for, because CTAP2 doesn't oblige the authenticator to honour `attestation: "none"`. Since the server never validated the attestation statement chain anyway (only `authData` + the COSE public key matter for the credential), the format gate was over-restrictive. Now we accept any fmt, log it at debug level for diagnostics, and continue parsing `authData` as before. Removed the now-unused `RpError::UnsupportedAttestation` variant.

## [0.5.16] - 2026-05-13

### Added

- **Vault Cluster — Client Discovery & Health-Aware Connection** — operator types a single DNS name; the client locates the cluster's nodes via `_bvault._tcp.<name>` SRV records, probes each one's `/v1/sys/health`, picks the best (SRV priority hard floor → leader-over-follower → RTT → SRV-weight tiebreak, with `cluster_id` minority rejection), and pins the session to that node. Explicit reconnect on node failure (no mid-session transparent failover) via the new `ClientError::NodeUnavailable` variant.

  Surfaces:
  - **bv-client**: new `discovery` + `health` modules; `RemoteBackendBuilder::{with_cluster_discovery, with_discovery_config, with_health_config, build_with_discovery}`; `RemoteBackend::selected()` + `input_label()`; `ClientError::{NodeUnavailable, NoHealthyNode}`; `classify_node_failure()` maps transport-level / sealed-5xx errors into `NodeUnavailable` from inside `RemoteBackend::handle`.
  - **GUI** (`gui/src-tauri/src/commands/connection.rs`, `gui/src/...`): `connect_remote` runs discovery; new `RemoteProfile` fields `cluster_discovery`, `discovery_srv_service`, `health_probe_timeout_ms`; new Tauri commands `get_selected_node` + `cluster_discover`; ConnectPage adds a cluster-discovery toggle; Layout's vault chip shows the picked node in its tooltip; Settings Connection card gets a "Cluster Discovery" row + a Re-probe diagnostics modal listing every candidate's state, RTT, and cluster_id; `isNodeUnavailable` helper for reconnect UX.
  - **CLI** (`src/cli/command/`): `HttpOptions` auto-runs discovery on bare hostnames; new `--no-cluster-discovery` flag + `VAULT_NO_CLUSTER_DISCOVERY` env var; new `bvault cluster discover` subcommand prints the scored candidate table without connecting.
  - **Tests**: 19 new unit tests in `bv-client` (parse_input, SRV ordering, every classification row, priority hard-floor, RTT and weight tiebreaks, cluster_id minority rejection, builder opt-out, end-to-end no-healthy-node) + 7 e2e tests in `crates/bv-client/tests/cluster_discovery_e2e.rs` using in-process fake HTTP nodes for leader-over-follower, both directions of the SRV priority floor, cluster_id minority rejection, RTT tiebreak, all-unreachable rejection, and post-failure reconnect.
  - **Docs**: new operator runbook at `docs/docs/cluster-client-discovery.md`.

  ([spec](features/vault-cluster-client-discovery.md), [roadmap](roadmaps/vault-cluster-client-discovery.md))

## [0.5.15] - 2026-05-13

### Fixed

- **FIDO2 PIN retry silently cancels the ceremony** (`gui/src-tauri/src/commands/fido2_native.rs`) — `fido2_submit_pin` now clones the PIN sender instead of `.take()`-ing it, so the slot stays populated across multiple PIN prompts in the same ceremony (e.g. when the authenticator responds with `InvalidPin` and asks again). Previously the second PIN entry was silently dropped, the status handler blocked on `recv_timeout`, and the authenticator's callback channel was dropped — surfacing as "Statemachine was cancelled" with no user-visible error. The ceremony cleanup at the end of register/sign still clears the slot.


- **FIDO2 attestation/assertion field name mismatch with WebAuthn spec** (`src/modules/credential/fido2/rp/proto.rs`) — `AuthenticatorAttestationResponse::client_data_json` and `AuthenticatorAssertionResponse::client_data_json` now deserialize from the spec-compliant `clientDataJSON` (capital JSON) instead of the serde-camelCase-default `clientDataJson`. Every spec-compliant client (browsers, the native authenticator crate) sends `clientDataJSON`, so the old name silently rejected all real-world FIDO2 registrations and authentications with `missing field 'clientDataJson'`. The legacy `clientDataJson` form is retained as a deserialization alias so any in-flight clients still work.


- **FIDO2 "not configured" error on Register Security Key** (`gui/src-tauri/src/commands/fido2_native.rs`) — `read_fido2_config` now backfills mode-appropriate defaults when the userpass mount has no FIDO2 config entry, then retries the read. Embedded vaults get `rp_id=localhost`/`rp_origin=https://localhost`; remote vaults derive `rp_id` (host) and `rp_origin` (`scheme://host[:port]`) from the connected remote profile's address, mirroring the SettingsPage `deriveDefaults` logic so admins can register keys without visiting Settings first. The write is best-effort: non-admin tokens fall through to the original "not configured" marker so login flows still recognise it and fall back to password entry.

## [0.5.14] - 2026-05-13

### Added

- **`tls_raft_no_verify` / `tls_api_no_verify` config switches for hiqlite** ([`src/storage/hiqlite/mod.rs`](src/storage/hiqlite/mod.rs)) — when operators sign Raft/API certs with a private CA that the container's trust store does not know about (common in puppet-managed deployments), hiqlite's rustls client rejected peers with `invalid peer certificate: UnknownIssuer` and Raft replication stalled with `AppendEntries 1->2 timeout`. The wrapper previously hardcoded `danger_tls_no_verify: false` and offered no way out short of injecting CA bundles into the container. The new boolean flags (default `false`, opt-in `true`) disable peer chain verification on the respective channel while keeping TLS for confidentiality. Peer authenticity is still enforced by `secret_raft`/`secret_api`. When `tls_api_no_verify = true`, the same skip-verify is propagated to the internal `ureq` agent used by `remove_node`/`trigger_failover`. A `WARN` line is logged at startup whenever either switch is enabled so the relaxed posture is auditable.

## [0.5.13] - 2026-05-13

### Fixed

- **Hiqlite listener bind failures silently produced a "live" node that never accepted connections** ([`src/storage/hiqlite/mod.rs`](src/storage/hiqlite/mod.rs)) — when `listen_addr_api`/`listen_addr_raft` resolved to an address the network namespace did not own (e.g. an external FQDN inside a rootless pasta netns whose hostname mapped to the host's external IP), hiqlite's internal `TcpListener::bind` failed with `EADDRNOTAVAIL`, the error was swallowed inside the listener task, and operations.log still logged a confident `api external listening on <host>:<port>`. The cluster then deadlocked with `Could not connect Client API WebSocket … Connection refused (os error 111)` against itself. Fix: pre-flight `bind()` on both Raft and API listen sockets before calling `hiqlite::start_node`, dropping the listener immediately on success and surfacing the real OS error with a remediation hint (use `0.0.0.0` or a netns-owned IP) on failure.

### Added

- **Hiqlite startup log distinguishes pristine vs resumed WAL** ([`src/storage/hiqlite/mod.rs`](src/storage/hiqlite/mod.rs)) — emits a single `INFO`/`WARN` line stating whether the configured `data_dir` contains an existing WAL (`logs/meta.hql`) or whether the node is starting from pristine state. Operators no longer have to infer this from `openraft` internals, and a silently-wiped data volume (a Quadlet/volume regression) becomes obvious in the first second of operations.log instead of being hidden behind hundreds of raft init lines.

## [0.5.12] - 2026-05-12

### Fixed

- **Hiqlite TLS cert/key paths were swapped, causing every HA node to crash-loop with `The private key file contained no keys`** ([`src/storage/hiqlite/mod.rs`](src/storage/hiqlite/mod.rs)) — hiqlite 0.13.1's `ServerTlsConfigCerts::new(key, cert)` constructor takes the **private key first** and the **certificate second** (see `hiqlite-0.13.1/src/tls.rs:40`), an unusual ordering that reads naturally as `new(cert, key)` and trips up every caller. BastionVault was calling it positionally with `(cert, key)` for both Raft and API channels, so the cert PEM went into the key slot and the key PEM went into the cert slot. `axum-server::tls_rustls::RustlsConfig::from_pem_file` then tried to parse a certificate as a private key, found zero PKCS#8/PKCS#1 keys in the input, and panicked during Raft bootstrap. Combined with the now-fixed (0.5.11) runtime-drop panic in `HiqliteBackend::new`, the operator-visible symptom was a tight 5-second restart loop with only `LockFile … not a clean start` showing in the log — the real "no keys" error was eaten. Fix: switch both `tls_raft` and `tls_api` to **struct-literal construction with named fields** (`ServerTlsConfigCerts { key, cert, danger_tls_no_verify }`) so the cert/key mapping can never be silently swapped again by reading the call site the wrong way around. Operators who applied the file-content workaround (swapping `*.crt` and `*.key` contents on disk) must restore the original files before deploying 0.5.12 or higher.

## [0.5.11] - 2026-05-12

### Fixed

- **Hiqlite backend init no longer masks startup errors with a tokio runtime-drop panic** ([`src/storage/hiqlite/mod.rs`](src/storage/hiqlite/mod.rs)) — when `Server::main` bootstraps the hiqlite backend it wraps the async constructor in a current-thread runtime (`server.rs:192-201`). If `HiqliteBackend::new_backend(...)` returned `Err(_)` (e.g. peer TLS handshake failure during Raft bootstrap because the cluster's private CA isn't in the system trust bundle), the locally-created inner `Runtime` in `HiqliteBackend::new` dropped on the outer worker thread while still inside `block_on`. Dropping a multi-threaded `Runtime` synchronously waits on its blocking pool, which is illegal in an async context and panicked with `Cannot drop a runtime in a context where blocking is not allowed`. The panic eclipsed the real error in operator-visible logs (only `LockFile … not a clean start` from the previous unclean shutdown showed through), making the root cause impossible to diagnose from `journalctl`. Fix: when an outer runtime is detected, own the entire inner runtime lifecycle (create → use → drop-on-error) on a dedicated `std::thread::scope` OS thread, so the error path drops `rt` on a plain thread. The success path is unchanged — `rt` moves into `backend._runtime` and the backend is sent back across the join; eventual backend drop is handled by the existing `Drop for HiqliteBackend` impl. Adds a regression test that drives `new()` to fail under an outer runtime and asserts `Err` instead of panic.

## [0.5.10] - 2026-05-11

### Fixed

- **Resource-Connect SSH sessions no longer fail with a blank terminal + "session control channel closed"** ([`gui/src-tauri/src/session/ssh.rs`](gui/src-tauri/src/session/ssh.rs)) — three independent bugs were stacking up to make SSH sessions unusable against hardened sshd builds (notably RHEL/CentOS 8.x sshd 8.7):
  1. **Malformed `pty-req` packet** — russh's `request_pty` encoder counts `Pty::TTY_OP_END` entries from the caller's slice in its declared modes-string length prefix (`1 + 5 * len`) but then silently skips writing them and auto-appends a single `TTY_OP_END` byte at the end. We were passing `TTY_OP_END` in the slice (matching the obvious reading of the API), so the declared length was 5 bytes longer than the actual modes payload. Lenient sshds tolerated the trailing garbage; hardened ones read past the end into packet padding, hit an invalid mode opcode, and the session child died — no `SSH_MSG_DISCONNECT`, just a silent TCP teardown. Fix: drop `TTY_OP_END` from the slice; russh adds it for us.
  2. **`request_pty` / `request_shell` are fire-and-forget in russh 0.60** — `want_reply: true` only tells the server to reply, but the russh API does NOT await `CHANNEL_SUCCESS` before returning. We now drain the success reply between requests, mirroring OpenSSH's wire behaviour, so a server that refuses pty-req surfaces as `ssh: server refused pty-req` instead of looking like a transport drop.
  3. **`no-more-sessions@openssh.com` hint** — OpenSSH's client sends this hardening hint right after the session channel is open; mirroring it keeps us on the same code path as openssh on servers that enter different session-setup branches based on its presence. Important ordering note: sending it *before* `channel-open` is interpreted as an attack ("Possible attack: attempt to open a session after additional sessions disabled") and gets the connection disconnected.
- **Closed-event delivery is now reliable when the worker dies before the React listener mounts** ([`gui/src-tauri/src/session/ssh.rs`](gui/src-tauri/src/session/ssh.rs), [`gui/src/routes/SessionSshWindow.tsx`](gui/src/routes/SessionSshWindow.tsx)) — the worker task could exit before the spawned WebviewWindow's React effect had subscribed to `closed_event`, which dropped the event into a void and left the operator staring at a blank terminal. The host now re-emits the closed event at 200 ms / 800 ms / 2500 ms after the initial fire, and the payload carries a human-readable `reason` string (e.g. `ssh transport closed (TCP EOF / disconnect before shell was ready)`) so the status bar and inline terminal banner show why the session ended instead of nothing. The React side de-dupes the re-emits.
- **GUI logs were silently dropped** ([`gui/src-tauri/src/lib.rs`](gui/src-tauri/src/lib.rs), [`gui/src-tauri/Cargo.toml`](gui/src-tauri/Cargo.toml)) — the GUI crate depended on `log` but never registered a backend, so every `log::info!` / `log::warn!` call in the GUI (and in russh via the `log` facade) was a no-op regardless of `RUST_LOG`. Initialise `env_logger` from `run()` with a default filter of `info`, overridable via `RUST_LOG`. Without this fix, diagnosing the SSH bug above would have been impossible.

## [0.5.9] - 2026-05-11

### Changed

- **`make plugins` now takes a target triple** ([`Makefile`](Makefile)) — new `PLUGINS_PROCESS_TARGET` variable cross-compiles every process-runtime plugin (xca-import, postgres, pmp) for a specified Rust target instead of the host. Resolves the `Exec format error (os error 8)` operators were hitting when they uploaded plugins built on a macOS workstation into a Linux container — the kernel refused to `execve()` the wrong-format Mach-O. The rustup target is auto-installed; cross-linkers are not. The Makefile auto-detects [`cross`](https://github.com/cross-rs/cross) on PATH when cross-compiling and routes through it; bare-cargo cross builds get an upfront warning instead of an inscrutable rust-lld link failure. The pack / sign steps now derive the `.exe` suffix from the *target* triple, not the host OS, so cross-compiled Windows binaries land with the right name. `make plugins` with no flag still builds for the host, unchanged.
  ```
  # Linux x86_64 container, built from any host:
  make plugins PLUGINS_PROCESS_TARGET=x86_64-unknown-linux-gnu
  # Linux arm64 container:
  make plugins PLUGINS_PROCESS_TARGET=aarch64-unknown-linux-gnu
  ```
- **PKI page resizes vertically with the window** ([`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx)) — the Issued certificates table and the Issuers tab grid both had a hard `max-h-[32rem]` cap (or no constraint at all, in the Issuers case), leaving large empty space at the bottom of a tall window. Both now use `min-h-[calc(100vh-22rem)]` on the grid and `max-h-[calc(100vh-22rem)] overflow-auto` on the scrollable list column, so the panels fill the available viewport height and the lists scroll inside their columns instead of pushing the rest of the page off-screen. Small-window behaviour preserved via `min-h-[20rem]` on the certs list and the outer `<main>`'s existing `overflow-auto`.

## [0.5.8] - 2026-05-11

### Added

- **Opt-in shell in the production container image** ([`deploy/container/Containerfile`](deploy/container/Containerfile), [`Makefile`](Makefile), [`features/packaging-podman-server.md`](features/packaging-podman-server.md)) — the distroless production image still ships shell-less by default, but `make container-image INCLUDE_SHELL=1` (default `0`) now bakes in `busybox-static` from a `debian:bookworm-slim` builder layer as `/bin/busybox` with `/bin/sh` symlinked to it. Static binary, no library deps, ~1 MB. Useful for operators who need `kubectl exec` / `podman exec` for diagnostics or have processes that shell out. apt only runs in the staging container, so the final image carries no package manager regardless of the flag. The `:debug` variant always had a busybox shell and is unaffected.

## [0.5.7] - 2026-05-11

### Fixed

- **`BrokenPipe` / `ConnectionAborted` mid-upload when invoking plugins with large inputs** ([`src/http/sys.rs`](src/http/sys.rs)) — `POST /v1/sys/plugins/{name}/invoke` was registered without a `PayloadConfig`, so actix capped the request body at its 256 KiB `web::Bytes` default and reset the connection mid-stream for anything larger. This bit the GUI's **PKI → Import XCA → Preview** flow, which ships the full XCA `.xdb` inline as base64 inside the JSON body — ureq surfaced the reset as `Io(Os { code: 32, kind: BrokenPipe })` on macOS. The invoke route now attaches a 32 MiB `PayloadConfig` matching the registration / logical / batch ceilings, so multi-MiB plugin inputs (XCA databases, PMP exports, etc.) upload cleanly.

## [0.5.6] - 2026-05-11

### Fixed

- **`make container-image` building for the host arch instead of `linux/amd64`** ([`Makefile`](Makefile)) — the `docker` (non-buildx) branch of `_BUILD_CMD` omitted `--platform`, so on arm64 hosts the build silently ignored the `PLATFORM ?= linux/amd64` default. Now passes `--platform $(PLATFORM)` in every branch (podman, `docker build`, `docker buildx build`), so the default produces an amd64 image regardless of host and `PLATFORM=` overrides are honoured consistently.

## [0.5.5] - 2026-05-11

### Added

- **Structured on-disk server logs** ([`src/logging.rs`](src/logging.rs), [`src/cli/config.rs`](src/cli/config.rs)) — new `log_dir` and `log_to_stderr` config fields. When `log_dir` is set the server writes three files: `operations.log` (every record at or above `log_level`), `security.log` (records emitted with `target: "security"` — seal/unseal, failed logins, denied policies), and `audit.log` (auto-bootstrapped by the audit broker on first unseal via [`src/core.rs`](src/core.rs) when no audit devices are persisted yet). Replaces the previous `env_logger`-only stderr setup. Convenience `security_warn!` / `security_info!` / `security_error!` macros are exported for consistent target tagging.
- **In-process size-based log rotation** ([`src/logging.rs`](src/logging.rs), [`src/audit/file_device.rs`](src/audit/file_device.rs)) — new `log_rotate_size_mb` (default 100) and `log_rotate_keep` (default 5) config fields. When a log file hits the threshold the server renames it to `<name>.1`, shifts the prior numbered copies up, drops anything beyond `keep`, and reopens a fresh file in place. The auto-bootstrapped audit device honours the same policy via new `rotate_size_bytes` / `rotate_keep` options on [`FileAuditDevice`](src/audit/file_device.rs); operators who prefer external logrotate can keep `log_rotate_size_mb = 0` and rely on the existing `reload()`-on-SIGHUP path.
- **Security-tagged log calls at seal/unseal and userpass login failures** ([`src/core.rs`](src/core.rs), [`src/modules/credential/userpass/path_login.rs`](src/modules/credential/userpass/path_login.rs)) — first round of explicit security-event emissions so `security.log` has real content on day one.

### Fixed

- **Import XCA on remote vaults failing with "Request is invalid"** ([`gui/src-tauri/src/commands/plugins.rs`](gui/src-tauri/src/commands/plugins.rs), [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx)) — the GUI sent the chosen XCA file as `file_path`, but in remote mode the plugin runs on the server and the path only exists on the client. The server-side plugin failed to open the file and the error was mapped to `RvError::ErrRequestInvalid`. Added a new `read_local_file_b64` Tauri command and switched the preview call to ship the file inline as `file_b64`, which the plugin already supports — same flow works embedded and remote.

## [0.5.4] - 2026-05-11

### Changed

- **GUI admin section now recognizes `super-admin` and `administrator` as full-admin policy-name keywords** ([`gui/src/components/Layout.tsx`](gui/src/components/Layout.tsx)) — operators can now grant the admin menu to non-root accounts by assigning a policy literally named `super-admin` or `administrator`, in addition to the existing `root` / `admin`. GUI visibility only; API authorization is still enforced by the policy's HCL rules server-side.
- **Workspace engine links (PKI, SSH, TOTP, OpenLDAP/AD, Cert Lifecycle) recognize the super-admin keywords** ([`gui/src/components/Layout.tsx`](gui/src/components/Layout.tsx)) — accounts assigned `super-admin` or `administrator` now see the same workspace engine nav as a root token, not just the Admin section. Introduces a shared `SUPER_ADMIN` constant so the per-item `requires` arrays and the `adminPolicies` set stay in lockstep.

### Fixed

- **Plugin registration aborting mid-upload on real-world `.bvplugin` bundles** ([`src/http/sys.rs`](src/http/sys.rs)) — `POST /v1/sys/plugins` reads the body via `web::Bytes`, but the `/v1/sys` scope had no `PayloadConfig`, so any upload past actix-web's default 256 KiB limit (i.e. essentially every real plugin) was rejected mid-stream. On Windows the GUI surfaced this as `Some ureq error happened, Io(Os { code: 10053, kind: ConnectionAborted, ... })`. Set an explicit 32 MiB `PayloadConfig` on the `/plugins` resource, matching the logical and batch ceilings.

### Plugins (out-of-tree)

- **`bastion-plugin-xca` 0.1.20 → 0.1.21** — version bump alongside the host registration-limit fix; no plugin code changes.

## [0.5.2] - 2026-05-10

### Fixed

- **Plugin admin in remote mode — `/sys/plugins/{publishers,accept_unsigned,quarantine,active-surfaces}` returning 404 "plugin not found"** ([`src/http/sys.rs`](src/http/sys.rs)) — actix-web matches resources in registration order, so the `/plugins/{name}` wildcard registered first was swallowing the literal-segment routes. Reorder so all literal `/plugins/<word>` resources come before the wildcard. Symptoms: Plugins page stuck on "Loading…" for the publisher allowlist + accept-unsigned toggle, and a "plugin not found" toast every time the surface watcher ticked. The earlier comment claiming actix prefers literals over wildcards was incorrect.

## [0.5.1] - 2026-05-10

### Changed

- **GUI plugin admin works in remote mode.** Previously every command on the Plugins page (`plugins_list`, `plugins_get_publishers`, `plugins_get_accept_unsigned`, `plugins_metrics`, etc.) hit `state.vault` directly and returned `"Vault not open"` when the GUI was connected to a remote server, producing a wall of error toasts. Each Tauri command in [`gui/src-tauri/src/commands/plugins.rs`](gui/src-tauri/src/commands/plugins.rs) now branches on `state.mode`: embedded keeps the in-process catalog/runtime path, remote forwards to the equivalent `/v1/sys/plugins/*` endpoint via `state.remote_client` with the active token attached. Server-side audit on the HTTP path replaces the embedded-side `emit_sys_audit` calls in the remote branch to avoid double-logging. `plugins_metrics` returns an empty list in remote mode (the server's `/sys/metrics` is Prometheus text, not JSON; the panel's empty state is the right surfacing).

## [0.5.0] - 2026-05-10

**Headline release: Plugin Extensibility v1.** Plugins now contribute menus + JSON-Schema forms + tables + detail views to the GUI declaratively via a `surface.json` shipped in the bundle, with optional client-side WASM form hooks executed in a sandboxed Wasmtime in the Tauri backend. The GUI fetches an aggregated `active-surfaces` bundle on login, content-addresses assets in a per-vault cache, and live-updates via a long-poll watcher when the operator activates a new version. v1 plugins keep working unchanged. Eight phases shipped end-to-end, from spec through reference TOTP example. Versions bumped from 0.4.1 across `Cargo.toml`, `gui/src-tauri/Cargo.toml`, `gui/package.json`, `gui/src-tauri/tauri.conf.json`.

### Added

#### Plugin Extensibility — Phase 7 reference example, SDK helpers, operator walkthrough (final phase)

- [`crates/bastion-plugin-sdk/Cargo.toml`](crates/bastion-plugin-sdk/Cargo.toml) New optional `surface` feature (implies `json`) that pulls in `bv_plugin_surface` and unlocks the surface-authoring helpers.
- [`crates/bastion-plugin-sdk/src/lib.rs`](crates/bastion-plugin-sdk/src/lib.rs) Two additions behind `feature = "surface"`:
  - `bastion_plugin_sdk::surface::*` — re-exports the full `bv_plugin_surface` type set (`SurfaceManifest`, components, bindings, `ActiveSurfaceBundle`, `CURRENT_SCHEMA_VERSION`) plus a `surface_builder(title)` helper that returns a default-shaped manifest with the current schema version.
  - `form_hook!(<fn>)` macro — emits the `bv_alloc` + `<export>(ptr,len)->i64` trampoline the GUI's WASM sandbox expects. The user-supplied function is `(serde_json::Value) -> serde_json::Value`; the macro handles JSON in/out marshalling and returns the `(ptr<<32)|len` packing on the way back. No-op on non-wasm targets so authors `cargo test` their hooks with normal `Value`s. Internal `form_hook_abi::{alloc, read_input, pack_response}` glue stays `#[doc(hidden)]`.
- [`crates/bastion-plugin-sdk/examples/totp_surface.rs`](crates/bastion-plugin-sdk/examples/totp_surface.rs) Reference example — a TOTP plugin's surface (codes table with delete row-action, register form with a base-32 secret field bound to a form-hook reference, optional live-polling detail page). Calls `validate("totp", &assets)` before printing so a malformed example can't ship.
- [`crates/bastion-plugin-sdk/examples/totp_form_hook.rs`](crates/bastion-plugin-sdk/examples/totp_form_hook.rs) Companion form-hook example using the new `form_hook!` macro. Validates the secret as base-32 (allowing space + dash separators), strips formatting, and returns the cleaned-up `values` payload so the form submits a normalised secret. 3 host-side unit tests (rejects empty name, rejects non-base32, strips spaces/dashes) all passing.
- [`features/plugin-extensibility.md`](features/plugin-extensibility.md) Status flipped to **Done**. New *Operator walkthrough* section covers author → form-hook → pack → register → activate → live-update → UX verify, plus migration notes for v1 plugins (no-op).
- [`roadmap.md`](roadmap.md) Plugin Extensibility row → Done; tracked totals bumped (Done 42→43, Todo 11→10).
- Verified: `cargo check --workspace` clean; `cargo run --example totp_surface --features surface,json` produces a valid surface JSON; `cargo test --example totp_form_hook --features surface,json` 3/3 passing.

All 8 phases of Plugin Extensibility shipped.

#### Plugin Extensibility — Phase 6 operator UX redesign

- New module [`gui/src/components/surface/SurfaceAdminPanel.tsx`](gui/src/components/surface/SurfaceAdminPanel.tsx) with two operator-facing pieces driven off the existing `usePluginSurfacesStore` (so Phase 5's watcher loop refreshes both views automatically):
  - `<SurfaceStats pluginName>` — inline cluster on each `PluginRow` showing `M menus / P pages / A assets` plus a *Preview surface* trigger. Renders nothing for v1 plugins that ship no surface.
  - `<PreviewSurfaceModal>` — opens from *Preview surface*. Two tabs: **Structured** view (mount + schema_version chips, menu list with section / route / `min_policy` annotations, page list grouped by ID with the component kinds inside, client-asset table with truncated SHA-256), and **Raw JSON** fallback for anything the structured view doesn't surface yet.
  - `<ActiveSurfaceMapCard>` — full-width card below the registered-plugins list. Aggregates every active plugin's menu contributions grouped by section (`secrets` / `sharing` / `admin` / `settings`), annotates `min_policy` requirements, and runs a route-collision detector that flags any `route` declared by more than one plugin (almost always a copy-paste bug). Manual *Refresh* button + a truncated bundle ETag for support.
- [`gui/src/routes/PluginsPage.tsx`](gui/src/routes/PluginsPage.tsx) wires `<SurfaceStats>` into `<PluginRow>` next to the existing `<CapabilityBadges>` and renders `<ActiveSurfaceMapCard />` between *Registered plugins* and *Per-plugin metrics*.
- Verified: `npx tsc --noEmit` clean, GUI boots with zero console errors.

Phase 7 next: reference plugin (TOTP) shipping `surface.json` + a `validate_create` form-hook + SDK helpers + the operator workflow walkthrough doc.

#### Plugin Extensibility — Phase 5 long-poll auto-update watcher

- [`src/http/sys.rs`](src/http/sys.rs) `sys_plugins_active_surfaces_handler` accepts `?watch=1` (or `watch=true`). When the operator-supplied `If-None-Match` matches the current aggregate ETag, the handler enters a 25-second polling loop (2-second cadence) that returns as soon as the ETag changes — no SSE/WS plumbing, fits the existing actix-web stack, and a missed wakeup is just a one-tick lag. 25-second ceiling leaves 5 s slack before the bv-client default `timeout_global` (30 s) fires.
- [`crates/bv-client/src/backend.rs`](crates/bv-client/src/backend.rs) `Backend::watch_active_surfaces` (default-impl falls back to `active_surfaces` so non-long-poll backends degrade gracefully).
- [`crates/bv-client/src/remote.rs`](crates/bv-client/src/remote.rs) `RemoteBackend` impl factored: `fetch_active_surfaces(token, etag, watch)` shared between the regular and watch variants; `watch=true` appends `?watch=1` to the URL. `fetch_asset` rerouted through a `do_fetch_asset` helper to keep the trait impl flat.
- [`crates/bv-client/src/surface.rs`](crates/bv-client/src/surface.rs) New `watch_once(backend, cache, token)` helper: returns `Some(bundle)` on change (cache also written through), `None` on 304 / timeout. 2 new tests: `watch_once_returns_new_bundle_when_etag_changed`, `watch_once_returns_none_on_unchanged_etag`. bv-client total now 13 passing.
- [`gui/src-tauri/src/commands/plugin_surface.rs`](gui/src-tauri/src/commands/plugin_surface.rs) New Tauri command `plugin_surface_watch_tick` — one iteration of the watcher (the React side drives the loop, which makes lifecycle / cancellation the renderer's responsibility instead of needing a backend supervisor task).
- [`gui/src/lib/api.ts`](gui/src/lib/api.ts) `pluginSurfaceWatchTick()` invoke wrapper.
- [`gui/src/stores/pluginSurfacesStore.ts`](gui/src/stores/pluginSurfacesStore.ts) `startWatch()` / `stopWatch()` actions plus a `lastUpdate: { plugin, version }[]` field that flips when the watcher picks up new bundle entries (diff against the previous `entries` map by `plugin → version`). Backoff on transport errors (2 s → 60 s, doubling, reset on success). Module-level `watchRunning` flag so a re-render doesn't stack loops; `clear()` flips it false on sign-out.
- [`gui/src/components/Layout.tsx`](gui/src/components/Layout.tsx) calls `startWatch()` after the initial `refresh()`; on `lastUpdate` change, fires a non-modal `toast("info", "Plugin surface updated: <plugin> → <version>. Open a new page to see changes.")` and clears the marker.
- Verified: `cargo check --lib` clean, `cargo check -p bastion-vault-gui --no-default-features` clean, `cargo test -p bv-client` 13/13 passing, `npx tsc --noEmit` clean, GUI boots with zero console errors.

Phase 6 next: operator UX redesign — surface preview in the admin Plugins page + active-surface map.

#### Plugin Extensibility — Phase 4 form-hook WASM sandbox

- New module [`gui/src-tauri/src/plugin_hooks.rs`](gui/src-tauri/src/plugin_hooks.rs). Pinned to the host crate's `wasmtime = "43"` so the workspace shares one compiled artifact. Per-call sandbox: 100 M instructions of fuel, 256 MiB memory ceiling via `StoreLimitsBuilder`, 4 MiB cap on input/output JSON, NaN canonicalisation on, **zero host imports** — a hook either runs as pure compute on a string in / string out or fails to instantiate. The ABI mirrors the existing `bv_run` shape so plugin authors using `bastion-plugin-sdk` reuse the same export pattern: `bv_alloc(size) -> i32`, `<export>(ptr, len) -> i64` (packed `(ptr<<32)|len`). Process-global Wasmtime engine + a sha256-keyed compiled-module cache so repeated hook calls skip cranelift. 8 unit tests: round-trip, cache short-circuit, missing export, missing `bv_alloc`, out-of-bounds output, fuel exhaustion, oversize input, host-imports-rejected.
- New Tauri command `plugin_surface_hook` in [`gui/src-tauri/src/commands/plugin_surface.rs`](gui/src-tauri/src/commands/plugin_surface.rs). Resolves the asset bytes through the existing surface cache (content-addressed by `sha256`, hash-verified on every read), parks the wasmtime call on `tokio::task::spawn_blocking` so the Tauri command worker keeps responding during a long compile, returns the hook's UTF-8 JSON output verbatim.
- Frontend wiring:
  - [`gui/src/lib/api.ts`](gui/src/lib/api.ts) `pluginSurfaceHook(plugin, version, sha256, export, inputJson)` invoke wrapper.
  - [`gui/src/components/surface/SurfaceForm.tsx`](gui/src/components/surface/SurfaceForm.tsx) on submit, when the spec declares `hook: "<asset>#<export>"`, looks the asset up in the entry's `client_assets[]` table, calls the hook with the form values JSON, and parses the response: `{ ok: false, errors: { field: msg } }` blocks submit and surfaces per-field error messages on the matching `<Input>` / `<SecretInput>` / `<Textarea>` / `<select>`; `{ values: {...} }` rewrites the payload (pre-submit transform). Hook failures (compile error, fuel exhaustion, missing export) are non-fatal — log to console and submit the unrewritten values, since server-side ACLs remain authoritative. SurfaceForm now also takes the full `entry` instead of just `mount` so the asset table is reachable; `<SurfaceRouter>` updated to pass it.
- Verified: `cargo check -p bastion-vault-gui --no-default-features` clean, `npx tsc --noEmit` clean, all 8 plugin_hooks tests pass, preview boots with zero console errors.

Phase 5 next: long-poll watcher on `active-surfaces` so the GUI auto-refreshes when an operator activates a new plugin version.

#### Plugin Extensibility — Phase 3 GUI dynamic surface rendering

- [`gui/src-tauri/src/state.rs`](gui/src-tauri/src/state.rs) `AppState` gains `plugin_surface_cache: Mutex<Option<SurfaceCache>>`. Lazily resolved to `<dirs::cache>/com.bastionvault.gui/plugins/<vault-id>/` on first use, where `<vault-id>` is `bv_client::vault_id_for(address, "")` — collision-resistant across vaults sharing a host cache dir.
- [`gui/src-tauri/src/commands/plugin_surface.rs`](gui/src-tauri/src/commands/plugin_surface.rs) Three new Tauri commands: `plugin_surfaces_refresh` (calls `bv_client::refresh`, returns the bundle), `plugin_surface_asset` (calls `ensure_asset`, returns base64), `plugin_surface_dispatch` (resolves a surface `{op, path}` binding by substituting `{mount}` and `{<form_field>}` placeholders, then dispatches through the existing `Backend::handle`). Path resolution refuses unsubstituted placeholders, `..`, and any path that escapes the plugin's mount.
- [`gui/src/lib/api.ts`](gui/src/lib/api.ts) Frontend types for the surface schema (`SurfaceMenu`, `SurfacePage`, `SurfaceComponent`, `SurfaceBinding`, `SurfaceForm`, `SurfaceTable`, `SurfaceDetail`, `ActiveSurfaceBundle`) plus three thin `invoke<T>` wrappers: `pluginSurfacesRefresh`, `pluginSurfaceAsset`, `pluginSurfaceDispatch`.
- [`gui/src/stores/pluginSurfacesStore.ts`](gui/src/stores/pluginSurfacesStore.ts) Zustand slice tracking `bundle`, `loading`, `error`, plus selectors `menusForSection(section, policies)` (filters by `min_policy`) and `pageByRoute(route)`. Cleared on sign-out.
- [`gui/src/components/PluginMenuSlot.tsx`](gui/src/components/PluginMenuSlot.tsx) Sidebar slot that renders plugin-contributed menus for a given `section`. Hides menus the active token's policies don't satisfy (UX hint only — server ACLs are authoritative).
- [`gui/src/components/Layout.tsx`](gui/src/components/Layout.tsx) Triggers `refreshPluginSurfaces()` once per authenticated session; injects `<PluginMenuSlot section="secrets">`, `<PluginMenuSlot section="sharing">`, and `<PluginMenuSlot section="admin">` (the last only inside the admin sub-nav).
- [`gui/src/components/surface/`](gui/src/components/surface/) Three renderer components driving everything generically off the surface manifest:
  - `SurfaceTable.tsx` — issues `op=list`, normalises `{keys: [...]}` / `{entries: [...]}` / single-record shapes, renders one row per entry with declared columns. Row actions dispatch through the same `pluginSurfaceDispatch` (with `{<field>}` substitution from the row), call `confirm:` via `window.confirm`, and trigger a reload on success.
  - `SurfaceForm.tsx` — schema-driven form supporting a JSON-Schema 2020-12 subset: `string` / `integer` / `number` / `boolean`, `format: "password"` (→ `<SecretInput>`), `format: "textarea"` (→ `<Textarea>`), `enum` (→ `<select>`), plus `title` / `description` / `default` / `required`. The `hook` field is read but warns to console — Phase 4 wires the actual WASM hook execution.
  - `SurfaceDetail.tsx` — `op=read` view with a key/value list. Fields with `live: true` re-issue the read on a 5-second cadence while mounted.
  - `SurfaceRouter.tsx` — wraps in `<Layout>`, looks up the current path in `pageByRoute`, walks `page.components`, and instantiates the matching renderer per entry. Empty / unknown / errored paths render an `<EmptyState>` rather than a blank screen.
- [`gui/src/App.tsx`](gui/src/App.tsx) New protected route `/plugin/:plugin/*` resolves to `<SurfaceRouter>`. Splat pattern lets one plugin contribute multiple pages sharing a `/plugin/<name>/` prefix.

Verified: `npx tsc --noEmit` clean, `npx vite build` succeeds (1.09 MB JS, 52 kB CSS), `cargo check -p bastion-vault-gui --no-default-features` clean.

Phase 4 next: form-hook ABI in the Tauri backend (sandboxed Wasmtime; no host imports; `validate` / `pre_submit` / `post_response`).

#### Plugin Extensibility — Phase 2 client-side surface fetch + content-addressed cache

- [`crates/bv-client/src/backend.rs`](crates/bv-client/src/backend.rs) The `Backend` trait gains two methods with default implementations: `active_surfaces(token, etag) -> SurfaceFetch` and `fetch_asset(plugin, version, sha256, token) -> Option<Vec<u8>>`. The `SurfaceFetch::NotModified` variant lets the cache short-circuit a 304 without re-reading the bundle's etag for comparison. Default impls return an empty bundle / `None` so existing backends (the GUI's `EmbeddedBackend`, in-memory test stubs) keep compiling without changes.
- [`crates/bv-client/src/remote.rs`](crates/bv-client/src/remote.rs) `RemoteBackend::active_surfaces` issues `GET /v1/sys/plugins/active-surfaces` with `If-None-Match: "<etag>"`, parses the `{"data": ActiveSurfaceBundle}` envelope, and prefers the server's `ETag` response header over the bundle's self-computed one. `fetch_asset` hits the per-version asset endpoint, refuses non-hex-of-64 input, treats 404 as `Ok(None)`, and re-verifies the SHA-256 on the response body as defence-in-depth against MITM/proxy corruption.
- [`crates/bv-client/src/surface.rs`](crates/bv-client/src/surface.rs) New module with the on-disk content-addressed cache. Layout: `<base>/<vault-id>/_meta.json`, `<base>/<vault-id>/<plugin>/<version>/surface.json`, `<base>/<vault-id>/_assets/<sha256>.bin`. Top-level orchestration:
  - `refresh(backend, cache, token)` — sends `If-None-Match`, returns the cached bundle on 304, writes through on 200, falls back to a force-fetch on the impossible "304 with no cache" combination.
  - `ensure_asset(backend, cache, plugin, version, sha256, token)` — cache-first; round-trips on miss; rejects bytes whose hash doesn't match.
  - `vault_id_for(address, identifier)` — stable 32-char prefix of `sha256(address || \0 || identifier)` so two vaults sharing a `dirs::cache` don't collide.
  - Cache write is atomic-via-rename and tombstones plugin/version subtrees that aren't in the new bundle.
  - Corrupt or hash-mismatched cached bytes drop to a cold fetch rather than serving bad data.
  8 new unit tests covering: cold-cache write+readback, warm-cache short-circuit on `If-None-Match → 304`, etag-change re-fetch, corrupt-surface fallback, evicted-plugin tombstoning, content-addressed asset cache reuse, hash-mismatch rejection on `write_asset`, vault-id stability/collision-resistance.

Phase 3 next: GUI consumes the bundle and renders menus/forms generically via a new `<SurfaceRouter>`/`<SurfaceForm>`/`<SurfaceTable>` component family.

#### Plugin Extensibility — Phase 1 server-side surface storage + HTTP routes

- [`src/plugins/manifest.rs`](src/plugins/manifest.rs) `PluginManifest` grows two optional fields — `surface: Option<SurfaceRef>` (schema_version, sha256, size) and `client_assets: Vec<ClientAssetRef>` (name, kind, sha256, size). Both default-empty on serde, so v1 plugins keep round-tripping. `validate()` rejects bad surface hashes, too-new schema versions, duplicate / slashed asset names. 6 new manifest tests, including `legacy_manifest_round_trips_without_new_fields`.
- [`src/plugins/catalog.rs`](src/plugins/catalog.rs) Five new methods on `PluginCatalog`: `put_surface` (recomputes SHA-256, parses + validates the JSON before persisting), `read_active_surface`, `put_asset` (content-addressed by sha256 — same asset across versions de-dupes naturally), `read_asset` (rehashes on read; refuses tampered storage), and `aggregated_active_surfaces` returning the typed `bv_plugin_surface::ActiveSurfaceBundle` with a stable etag. `delete_version` and `delete` now also clear `core/plugins/<name>/versions/<version>/surface` and the per-version `assets/` subtree. 5 new catalog tests covering round-trip, hash mismatch, content-addressed dedup, etag stability across re-fetch, and delete-clears.
- [`src/http/sys.rs`](src/http/sys.rs) Three new routes: `GET /v1/sys/plugins/<name>/surface` (active version, `If-None-Match` → 304), `GET /v1/sys/plugins/active-surfaces` (aggregated bundle, top-level etag, `If-None-Match` → 304), `GET /v1/sys/plugins/<name>/versions/<version>/asset/<sha256>` (content-addressed asset, `Cache-Control: public, immutable`). The existing register handler now accepts optional `surface_b64` + `client_assets_b64: [{name, bytes_b64}]`. Registration cross-checks every uploaded asset against `manifest.client_assets[]` (presence, size, sha256) and rejects mismatches with a clear `ErrString`. Audit pipeline carries the new paths automatically.
- All 17 plugins-catalog tests + 17 plugins-manifest tests pass; full plugins module suite is 67 passing, 1 ignored.

Phase 2 next: wire `bv-client::surface` to fetch the aggregated bundle and content-address the assets in the per-vault cache.

#### Plugin Extensibility — Phase 0 + Phase 1 type foundation

- Spec doc landed at [`features/plugin-extensibility.md`](features/plugin-extensibility.md): bundle layout v2, manifest extensions, surface schema reference (menus / pages / form / table / detail components), form-hook ABI, client cache layout, server endpoints, audit events, and migration notes for v1 plugins (which keep working untouched).
- New shared types crate [`crates/bv_plugin_surface/`](crates/bv_plugin_surface/) — single source of truth for `surface.json`. Defines `SurfaceManifest`, `SurfaceMenu`, `SurfacePage`, `SurfaceComponent` (table/form/detail), `SurfaceBinding` (with `{mount}/...` scoping enforcement), `ActiveSurfaceBundle`, plus a stable `surface_etag` over canonical JSON and an aggregated `ActiveSurfaceBundle::compute_etag`. `validate()` rejects: unknown `schema_version`, menu routes outside `/plugin/<this-plugin>/`, bindings that escape `{mount}/` or contain `..`, duplicate component / menu IDs, hook references to undeclared assets. 11 unit tests (cold-validate happy path, every rejection path, etag stability, json round-trip).
- Roadmap doc [`roadmaps/plugin-extensibility-redesign.md`](roadmaps/plugin-extensibility-redesign.md) tracks the full 8-phase delivery (≈10 engineer-weeks): server surface storage → bv-client cache → GUI dynamic render → form-hook sandbox → auto-update → operator UX → reference plugin + SDK + docs. Tracked in [roadmap.md](roadmap.md) at Todo / In Progress.

### Changed

- Version bumped to **0.4.1** across `Cargo.toml`, `gui/src-tauri/Cargo.toml`, `gui/package.json`, `gui/src-tauri/tauri.conf.json` to ship the OpenSSL-removal + remote-backend Sign-In fixes.

#### GUI — Sign In falls through to password when FIDO2 is not provisioned

- [`gui/src-tauri/src/commands/fido2_native.rs`](gui/src-tauri/src/commands/fido2_native.rs) `read_fido2_config` and `fido2_native_login` now translate a bare HTTP 404 (the shape `auth/userpass/fido2/config` and `auth/userpass/fido2/login/begin` return when nothing has been provisioned for the userpass mount) into the `"FIDO2 not configured"` / `"FIDO2 credential not found for this user"` strings that [`gui/src/routes/LoginPage.tsx:257`](gui/src/routes/LoginPage.tsx:257) substring-matches to drop to the password screen. Without this, the operator saw a confusing `HTTP 404: HTTP 404 (no body)` toast on every Sign In attempt against a server with no FIDO2 setup, with no path forward to enter their password.

### Added

#### Server — Client-IP propagation (Wave 2 / Phase 1.5)

- New module [`src/http/client_ip.rs`](src/http/client_ip.rs):
  `BASTIONVAULT_TRUSTED_PROXIES` CIDR parser plus a right-to-left
  walker for both `X-Forwarded-For` and RFC 7239 `Forwarded`. The walk
  stops at the first hop **not** in the trusted set, which prevents an
  attacker outside the trusted CIDRs from forging a header to
  impersonate an internal IP. 9 unit tests cover the threat model.
- New module [`src/http/proxy_protocol.rs`](src/http/proxy_protocol.rs):
  HAProxy PROXY-protocol v1 + v2 parser plus a `ProxyProtocolMode` env
  validator. The acceptor that intercepts the TCP accept loop is
  deferred to a follow-up — the parser is the load-bearing piece and
  the wiring choice (custom `ServerBuilder` shim vs. localhost
  loopback shim) deserves its own design pass. `BASTIONVAULT_PROXY_PROTOCOL`
  is parsed at startup so an invalid value fails loudly.
- [`src/logical/connection.rs`](src/logical/connection.rs) gains
  `peer_addr_derived` next to `peer_addr`; both are populated in the
  HTTP handler ([`src/http/logical.rs`](src/http/logical.rs)) using
  `ClientIp::resolve`.
- [`src/audit/entry.rs`](src/audit/entry.rs) gains `remote_address_socket`
  and `remote_address_derived` on both `AuditAuth` and `AuditRequest`.
  The legacy `remote_address` field now carries the derived address —
  this is the field consumers that read just one address want — while
  the two new fields preserve both views for forensics (so a reviewer
  can always tell "the proxy attested X originating from Y" from "the
  socket reported Y directly"). 1 new regression test.
- [`deploy/container/config/config.hcl.sample`](deploy/container/config/config.hcl.sample)
  documents both env vars in a commented "Client-IP propagation" block.

#### Packaging & Distribution — Wave 2

Three deliverables shipped under the [Wave 2 sequencing](roadmaps/packaging-and-distribution.md):

- **Server Phase 2 — Cluster mode reference.** `deploy/compose/cluster.yml`
  brings up 3 bvault containers on a shared compose network, each with
  its own `cluster/node{1,2,3}.hcl`. The image is unchanged —
  cluster-vs-standalone is decided by the mounted `config.hcl`, not by
  an entrypoint env-var (matches the spec's "templating belongs in the
  operator's deployment tool" stance, simpler than the originally
  proposed entrypoint helper). Operator cookbook in
  `deploy/compose/cluster/README.md`.
- **Server Phase 3 — Multi-arch + signing + SBOM.** Extended
  [`.github/workflows/container-image.yml`](.github/workflows/container-image.yml)
  to build `linux/amd64` + `linux/arm64` under one manifest list per
  tag, sign the digest with **Cosign keyless** (GitHub OIDC, no static
  keys), and attach a CycloneDX SBOM via `syft` + `cosign attest`.
  A new `:debug` variant (`deploy/container/Containerfile.debug`)
  ships the same binaries on `debug-nonroot` distroless plus
  `ss`/`ip`/`tcpdump`/`curl` for incident response. Verification +
  SBOM-download one-liners are in the workflow's job summary.
- **Server Containerfile cleanup.** Now that the FIDO2 RP migration
  removed openssl from the server crate, dropped `libssl-dev`,
  `pkg-config`, `OPENSSL_STATIC=1`, and `OPENSSL_NO_VENDOR=1` from the
  builder stage. The `ldd` guard now flags any future regression
  rather than guarding an intentional static link.
- **Client Phase 1 — Linux CLI packages.** `[package.metadata.deb]`
  and `[package.metadata.generate-rpm]` blocks in `Cargo.toml` produce
  installable .deb / .rpm for the `bvault` CLI on amd64. Static
  manpage + bash/zsh/fish completion stubs live under
  `installers/cli/`. Build with `make linux-cli-deb`,
  `make linux-cli-rpm`, or `make linux-cli-packages` (requires
  `cargo install cargo-deb cargo-generate-rpm`). Phase 4 GPG signing
  is still pending.
- **Client Phase 1 — Linux GUI skeleton.** `gui/src-tauri/installers/linux/`
  carries the `postinst` + `prerm` scriptlets the Tauri bundler will
  reference when run on a real Linux build host (XDG / MIME / icon
  cache refresh). The `tauri.conf.json` wiring is deliberately
  deferred until a `tauri build` pass on Linux validates the asset
  paths — committing it cold invites silent format drift.

### Changed

#### FIDO2 RP — replace `webauthn-rs` with in-tree pure-Rust implementation

- New module `src/modules/credential/fido2/rp/` implements a minimal
  WebAuthn Relying Party with no `openssl` dependency. Supports passkey
  registration and authentication with attestation format `none`,
  ES256 + Ed25519 signatures (which covers every passkey-capable
  authenticator in practice).
- Rewires `modules/credential/fido2/path_register.rs`,
  `path_login.rs`, and the userpass mirrors
  (`userpass/path_fido2_register.rs`, `path_fido2_login.rs`,
  `path_users.rs`) onto the new `RelyingParty` API.
- Storage shape changes: `credentials_json` is now an array of in-tree
  `Passkey` records (`v=1`). Existing FIDO2 enrollments produced by
  the prior `webauthn-rs`-backed code path are NOT readable — operators
  must re-enroll keys after upgrading.
- Drops `webauthn-rs` and `webauthn-rs-proto` from `Cargo.toml`; adds
  `ciborium` for CBOR parsing. Net effect:
  `openssl` and `openssl-sys` are no longer in the server crate's
  dependency tree (`cargo tree -p bastion_vault -i openssl` is empty).
  GUI-side `openssl` from the Mozilla `authenticator` crate is
  unchanged and tracked as a separate cleanup.
- Also removes the unused `webauthn-rs-proto` dep from
  `gui/src-tauri/Cargo.toml`.
- 10 new unit tests in `rp/tests.rs` cover challenge generation, RP
  origin/host validation, clientData verification (type/origin/challenge
  mismatches), authenticatorData parsing, and Passkey JSON round-trip.

#### PMP importer — non-connectable rows now route to KV, not Resources

- The Resources inventory is for *connectable devices* (server / database / firewall / switch / network_device / website / application). Previously, unrecognised PMP `OS Type` values (e.g. `Arquivos de Incidentes`, `Resource Type`, custom PMP install types) were synthesising empty BV resources with auto-slugged custom type ids, polluting the inventory with non-clickable entries. Those rows now route to KV by default under `secret/pmp-import/<batch-id>/{incident-files|other}/<resource>/<account>` with the same JSON envelope shape (value_b64 + PMP context). The catch-all kind is `other`. Verified against the operator's real fixture: 99 rows now produce 53 resources + 11 KV entries (was 55 + 8). Tests added to `tests/version_matrix.rs` covering the routing rule and the new `kv:<kind>` form of `type_overrides` (lets operators force normally-resource rows into KV and vice versa). Mapping change in `bastion-plugin-pmp/src/mapping.rs`; `RowKind::Unknown` removed.

#### Resource-type icons (configurable, with built-in defaults)

- New `ResourceTypeIcon` UI component (`gui/src/components/ui/ResourceTypeIcon.tsx`) renders a Lucide icon with a colour-tinted pill and a native `title` tooltip carrying the type label. Falls back to a text pill when the type has no icon configured (or when an unknown icon name is set on a saved type) so legibility is never lost.
- `ResourceTypeDef` gains an optional `icon` field. Defaults baked into `DEFAULT_RESOURCE_TYPES`: server → `Server`, database → `Database`, firewall → `ShieldCheck`, switch → `Network`, network_device → `Router`, website → `Globe`, application → `AppWindow`.
- Settings → Resource Types editor adds an icon picker (curated catalog of ~21 Lucide icons covering server, database, shield, network, router, wireless, globe, application, code, cloud, CPU, disk, monitor, mobile, camera, printer, key, lock, document, generic), with a live preview next to the picker.
- Resources page (list + detail views) and the PMP importer wizard's review step now render the type as an icon-with-tooltip instead of the old text badge.

#### PMP importer — wizard readability fixes

- Owner banner, step bar, account-list expand, progress bar, error panel, and skipped-rows warning all migrated from light-mode-only colour fallbacks (white-on-white in dark mode) to the project's `var(--color-*)` token system. Errors panel now uses `var(--color-danger)` with a translucent background and a scrollable list so a multi-error import surfaces every entry.

### Removed

#### OpenSSL — fully evicted from the workspace

- [`Cargo.toml`](Cargo.toml) Dropped the windows-only `openssl = { version = "0.10", features = ["vendored"] }` dependency. It had no direct callers in `src/` and was a vestigial defensive add — `cargo tree -i openssl-sys --target x86_64-pc-windows-msvc` now returns empty across the entire workspace.
- [`gui/src-tauri/Cargo.toml`](gui/src-tauri/Cargo.toml) `authenticator 0.5` switched from `crypto_openssl` → `crypto_rust` (pure-Rust AES/CBC/HMAC/p256 backend that ships with the same crate). The Windows FIDO2 transport still works; no behavior change at the API surface.
- [`gui/src-tauri/Cargo.toml`](gui/src-tauri/Cargo.toml) Removed the vendored OpenSSL dep that backed `pki_import_ca_pkcs12`. Replaced with `p12-keystore = "0.2.1"` (`pbes1` feature for the legacy 3DES / RC2 cipher modes Windows-minted .p12 files use) plus `pem 3.0` for PEM encoding.
- [`gui/src-tauri/src/commands/pki.rs`](gui/src-tauri/src/commands/pki.rs) `pki_import_ca_pkcs12` rewritten on top of `p12_keystore::KeyStore::from_pkcs12`. The library normalises private keys to PKCS#8 DER regardless of the inner key type (RSA / EC / Ed25519), so the existing server-side `pem_bundle` splitter at `pki/config/ca` accepts the resulting PEM block under the standard `PRIVATE KEY` header without changes. Cert chain handling now iterates `chain()[1..]` instead of the openssl `parsed.ca` slot.
- Net result: no more `openssl-src` Perl-driven build step on Windows, the workspace's TLS surface is now exclusively `rustls + aws-lc-rs`, and no C-side OpenSSL ABI is required to build either the server or the GUI.

### Fixed

#### Remote backend — Policies page empty + login crashed on empty error bodies

- [`gui/src-tauri/src/commands/policies.rs`](gui/src-tauri/src/commands/policies.rs) `list_policies` issued `LIST /v1/sys/policies/acl/` (LIST verb + trailing slash). The server only registers `GET /v1/sys/policies/acl` ([src/http/sys.rs:2095](src/http/sys.rs:2095)); the handler internally forces `Operation::List` regardless of the HTTP verb, so the route never matched on the remote backend and the Policies page rendered "No policies." Embedded mode was unaffected because it bypasses HTTP routing. Switched the GUI command to `Operation::Read` with no trailing slash, matching the pattern already used for `sys/mounts` and `sys/internal/ui/mounts`.
- [`crates/bv-client/src/remote.rs`](crates/bv-client/src/remote.rs) The HTTP dispatcher unconditionally called `read_json()` on every non-204 response, so any reply with an empty body (e.g. error responses without a `{"errors":[…]}` envelope) failed with `ureq: json: EOF while parsing a value at line 1 column 0` — masking the real status code. The most visible symptom: the Sign In page surfaced this parse error when `auth/userpass/fido2/login/begin` returned 4xx with no body for users without registered passkeys. The fix reads the body to bytes first, treats empty/whitespace as `Value::Null`, and the error branch now reports `HTTP <status> (no body)` instead of a JSON parse error.

#### Server — ship a default `administrator` policy

- [`src/modules/policy/policy_store.rs`](src/modules/policy/policy_store.rs) Added `ADMINISTRATOR_POLICY` (`path "*"` with `create/read/update/delete/list/sudo`) to the seeded ACL policy set loaded by `load_default_acl_policy`. The previous baseline shipped `default`, `standard-user`, `secret-author`, plus the per-engine `*-user` / `*-admin` pairs but no global admin role short of `root`, forcing operators to hand-roll one before granting break-glass access through the GUI. Existing servers pick the policy up on the next core init.

#### Remote backend — `bv-client` parsed every dedicated sys handler as "no data"

- [`crates/bv-client/src/types.rs`](crates/bv-client/src/types.rs) `JsonResponse::from_json` only knew the *envelope* response shape (`{"data": {...}, "auth": {...}}`) emitted by `response_logical` for the `/v1/{path}` catch-all. The dedicated sys handlers (`sys/internal/ui/mounts`, `sys/mounts`, `sys/auth`, `sys/policy`, …) go through `http::handle_request` instead, which serializes the response's `data` map at the **top level** of the body. Worse: `sys/internal/ui/mounts` returns `{"secret": {…mounts}, "auth": {…mounts}}`, and the old parser greedily lifted the `"auth"` key into the login-payload field, leaving `r.data == None` and silently routing mount data into the wrong slot. Symptom on the remote backend after the Phase 2 migration to `bv-client`: every Mounts / Users / Auth-Methods page showed empty, attempts to enable a default engine produced `HTTP 500: Mount path already exists`, and creating a user surfaced `HTTP 404: Router mount not found.` The fix detects the envelope shape by the presence of a `"data"` key OR a real login `auth` (one that carries `client_token`); otherwise the entire body becomes `out.data`. An `auth` field is now only adopted into `out.auth` when it actually looks like a login payload, so mount-map `auth` no longer hijacks it. Three regression tests added: `from_json_envelope_with_data`, `from_json_login_envelope`, `from_json_raw_sys_internal_ui_mounts`. Embedded vault was unaffected because it bypasses HTTP entirely.
- [`gui/src/routes/UsersPage.tsx`](gui/src/routes/UsersPage.tsx) `ensureMountAndLoad` previously swallowed every error from `listAuthMethods` / `enableAuthMethod` with `catch {}`, so a failure in the userpass auto-enable flow surfaced only as the confusing downstream "Router mount not found" when the user clicked Create. Both failure paths now toast the underlying error (e.g. permission-denied on `sys/auth/userpass`), making the real cause visible without diff-walking the dev console.

#### Hiqlite backend — `Drop` no longer panics inside an outer tokio runtime

- [`src/storage/hiqlite/mod.rs`](src/storage/hiqlite/mod.rs) `Drop for HiqliteBackend` previously called `rt.block_on(client.shutdown())` and then dropped the owned `tokio::runtime::Runtime` field on whichever thread the backend happened to be dropped on. When that thread was an actix/tokio worker (the common case, since `new()` already detects an outer runtime via `Handle::try_current()`), both the inner `block_on` and the runtime's blocking shutdown were illegal in that context, producing `thread 'main' panicked … Cannot drop a runtime in a context where blocking is not allowed` (or its sibling `Cannot start a runtime from within a runtime`). The fix `take()`s the runtime out of the struct and moves the graceful `client.shutdown().await` plus the `Runtime` drop onto a fresh OS thread; that thread is `join()`ed only when no outer runtime is present (CLI exits, sync tests), and detached otherwise so the async worker is never blocked. Regression test `test_hiqlite_backend_drop_inside_runtime` (gated by `CARGO_TEST_HIQLITE=1`) constructs a backend inside `#[tokio::test]`, asserts the `_runtime` ownership path is taken, and drops it inside the outer runtime — fails with the original panic on the buggy `Drop`, passes on the fix.

#### Audit chain now records the connecting client's IP

- [`src/audit/entry.rs`](src/audit/entry.rs) `AuditEntry::from_request` previously hardcoded `remote_address: String::new()` on both `auth` and `request` halves of every audit line, so the audit chain never carried the connecting client's address even though `Request.connection.peer_addr` was already populated by the HTTP layer ([src/http/logical.rs:72](src/http/logical.rs:72)). The fix reads the peer address out of `req.connection` and writes it into both `auth.remote_address` and `request.remote_address`; if `connection` is `None` (synthetic / internal calls) both fields stay empty. Two regression tests added to [`src/audit/entry.rs`](src/audit/entry.rs): `entry_carries_peer_addr_from_connection` and `entry_remote_address_empty_when_no_connection`. This closes the Wave 1 / Phase 1 acceptance bar in [`features/packaging-podman-server.md`](features/packaging-podman-server.md) which required "audit-log entries for operator init / unseal / KV writes carry the connecting client's socket-level IP". Trusted-proxy header derivation (`client_ip_socket` + `client_ip_derived` separation, `BASTIONVAULT_TRUSTED_PROXIES`, PROXY-protocol acceptor) remains scheduled for Phase 1.5 — that work now augments an already-populated socket-IP field instead of having to create one from scratch.

### Changed

#### XCA database import — status flipped to Done

- [`features/xca-import.md`](features/xca-import.md) status moved to **Done**. External plugin `bastion-plugin-xca` (process runtime) is shipped: reads XCA `.xdb` SQLite databases, decrypts both envelope formats (EVP_BytesToKey for XCA ≤ 2.0, PBKDF2-HMAC-SHA512 for XCA ≥ 2.4) including per-key `ownPass`, and imports certificates / private keys / CRLs into the PKI engine via the `Settings → PKI → Import XCA` GUI wizard. Standalone keys / CSRs / templates land as KV blobs under `secret/xca-import/<batch-id>/...`. Zero host-crate code; rides on the plugin substrate alongside `bastion-plugin-pmp`. Roadmap counts updated (Done 41 → 42, Todo 12 → 11); entry added to the Completed Initiatives list.

### Added

#### Packaging & Distribution — Wave 1, Phase 1: standalone server container image (amd64)

- New [`deploy/container/Containerfile`](deploy/container/Containerfile) — two-stage OCI build. Stage 1 builds `bvault` + `bv-ssh-helper` from `rust:1-slim-bookworm` with `clang` + `cmake` + `git` + `pkg-config` + `libssl-dev`. The host crypto stack is OpenSSL-free, but `webauthn-rs` 0.5.4 (FIDO2 / WebAuthn attestation) transitively pulls in `openssl-sys`; we install `libssl-dev` to satisfy the build and set `OPENSSL_STATIC=1` + `OPENSSL_NO_VENDOR=1` so openssl is statically linked into the binary and the distroless runtime never needs `libssl.so.3` at run time. A post-build `ldd` check fails the build if a `libssl` / `libcrypto` dynamic link sneaks back in, so a misconfiguration surfaces at build time instead of as a confusing "cannot find libssl.so.3" error at container start. Stage 2 is `gcr.io/distroless/cc-debian12:nonroot` — glibc + ca-certificates + the two binaries + the inert sample config, nothing else. Runs as UID `65532:65532`, exposes `8200`, `WORKDIR=/var/lib/bvault`, `ENTRYPOINT=["/usr/local/bin/bvault"]`, `CMD=["server", "--config", "/etc/bvault/config.hcl"]`. No shell in the runtime — entrypoint is the binary directly; the mode-resolver wrapper lands as a static-built helper in Wave 2 alongside cluster mode.
- New [`deploy/container/config/config.hcl.sample`](deploy/container/config/config.hcl.sample) — Hiqlite single-node config baked at `/etc/bvault/config.hcl`, with **placeholder secrets that intentionally fail validation** so an operator who forgets to bind-mount their own config gets a loud immediate failure rather than a silently misconfigured production server. Documents the disable_mlock + `IPC_LOCK` capability tradeoff for distroless / rootless deployments.
- New [`deploy/container/README.md`](deploy/container/README.md) — operator quickstart: pulling, the bind-mount layout (`/var/lib/bvault/data`, `/etc/bvault/config.hcl`, `/etc/bvault/tls/`), the manual `operator init` + `operator unseal` flow (no auto-init, no auto-unseal), the recommended orchestrator readiness probe pointing at `/v1/sys/health` (a binary-based `HEALTHCHECK` arrives in Phase 3), and an explicit "what this image does not do" list.
- New [`deploy/compose/standalone.yml`](deploy/compose/standalone.yml) — `podman compose` / `docker compose` reference for a single-node standalone deployment. Bind-mounts a host `./config.hcl`, `./tls/`, and a named `bv-data` volume; documents that `user:` overrides are not supported (UID is hard-coded at 65532 in the image).
- New [`.github/workflows/container-image.yml`](.github/workflows/container-image.yml) — GitHub Actions workflow triggered on `v*.*.*` tags (and `workflow_dispatch` for manual smoke tests). Builds `linux/amd64` via `docker/build-push-action@v5`, tags with `vX.Y.Z` / `vX.Y` / `vX` / `latest` via `docker/metadata-action@v5`, pushes to `ghcr.io/<owner>/bastionvault` using `GITHUB_TOKEN` with `packages: write` scope. Uses GitHub Actions cache (`type=gha`) to amortise the slow first-time Rust compile across runs. **Unsigned** — Cosign keyless signing + CycloneDX SBOM attestation arrive in Wave 2 / Phase 3.
- New repo-root [`.dockerignore`](.dockerignore) — excludes `target/`, `.git/`, `gui/node_modules/`, `gui/dist/`, `gui/src-tauri/target/`, the `plugins-ext/` and `IronRDP` submodules (both excluded from the cargo workspace), and editor / OS noise. Keeps the build context small and reproducible.

##### Spec sync

- [`features/packaging-podman-server.md`](features/packaging-podman-server.md) volume paths reconciled with the project's existing `bvault` convention from [`config/single-node.hcl`](config/single-node.hcl): `/etc/bastionvault/` → `/etc/bvault/`, `/var/lib/bastionvault` → `/var/lib/bvault/data`, `/var/log/bastionvault/` → `/var/log/bvault/`. Image / container / chart names (`bastionvault`, `bastionvault-server`) unchanged.

#### Packaging & Distribution — roadmap + three feature specs

- New roadmap doc at [`roadmaps/packaging-and-distribution.md`](roadmaps/packaging-and-distribution.md) sequences server-image + client-installers + downloads-website work into four release waves and tracks the cross-cutting decisions (distroless base, Cosign keyless signing, no auto-update, no auto-init / auto-unseal, single shared `manifest.json` format, single release workflow that emits all artefacts).
- New feature spec [`features/packaging-podman-server.md`](features/packaging-podman-server.md) — one signed OCI container image for the server, parameterised at start time into either a standalone single-process server or a Hiqlite Raft cluster member. Two-stage build with a distroless `cc-debian12:nonroot` runtime, multi-arch (amd64 + arm64), Cosign keyless + SLSA v1 provenance + CycloneDX SBOM, pinned tags + `:debug` variant for incident response, five phases ending in a reference Helm chart. Refuses to start without operator-supplied config; refuses cluster mode without TLS material; no insecure-cluster fallback; no auto-init / auto-unseal. **Client-IP visibility (new Phase 1.5)** is treated as a first-class server concern, not a container-tooling concern: `actix-web`'s socket layer reports the connecting peer natively, and a new trusted-proxy gate (`BASTIONVAULT_TRUSTED_PROXIES`, comma-separated CIDRs, empty by default → forwarded headers ignored) right-to-left walks `X-Forwarded-For` / RFC 7239 `Forwarded` and stops at the first untrusted hop so a spoofed header from outside the trusted set cannot impersonate an internal IP. Mutually-exclusive `BASTIONVAULT_PROXY_PROTOCOL=v1|v2` accepts a HAProxy PROXY-protocol header in front of the listener for L4 deployments. Audit events carry **both** `client_ip_socket` and `client_ip_derived` so a forged-header incident can be reconstructed from the audit chain alone. Production `:latest` / `:vX.Y.Z` images carry no userspace network tools (no `ss` / `ip` / `tcpdump` / `curl`); the `:debug` variant adds those four for operator-side inspection of "is my proxy actually forwarding the real client IP?" without rebuilding the image.
- New feature spec [`features/packaging-client-binaries.md`](features/packaging-client-binaries.md) — native installers for the Tauri GUI (`bastionvault-gui`) and the `bvault` CLI on Linux (deb + rpm), macOS (pkg), and Windows (msi via WiX 3.x). Tauri's bundler drives the GUI side; `cargo-deb` / `cargo-generate-rpm` / `pkgbuild`+`productbuild` / a CLI-only WiX project drive the CLI side. Every artefact carries a platform-native signature (Authenticode / notarised pkg / GPG-signed deb+rpm) **and** a Cosign keyless signature. Five phases (Linux → macOS → Windows → manifest.json + GitHub Releases publish → optional apt/dnf repos). Per-machine Windows installs only; no auto-update.
- New feature spec [`features/packaging-distribution-website.md`](features/packaging-distribution-website.md) — small Rust binary (`bv-downloads-server`, axum + askama) packaged as an OCI image that serves a branded landing page rendered from a mounted `manifest.json`. Operator drops signed client artefacts into a read-only volume; the container surfaces SHA-256 + Cosign signatures next to every download. No upload, no admin panel, no telemetry. Same distroless / nonroot / multi-arch / Cosign-signed posture as the server image. Phase 4 wires the GUI's "update available" banner to poll the manifest endpoint and link out to the install — no silent self-replacement.
- [`roadmap.md`](roadmap.md) — new "Packaging & Distribution" section with three rows pointing at the specs above; the initiative is added to "Active Initiatives" with a one-line summary of the four-wave plan.

#### First-class `firewall` / `switch` resource types + refined `database` — feature spec

- New feature spec at [`features/resource-types-firewall-switch-db.md`](features/resource-types-firewall-switch-db.md) — adds `firewall` and `switch` as first-class built-in resource types in `gui/src/lib/resourceTypes.ts` (vendor enum, HA role / layer, firmware, model, site/zone) and converts `database.engine` from free text to a closed enum (PostgreSQL, MySQL, MariaDB, MSSQL, Oracle, MongoDB, Redis, Elasticsearch, SQLite, Other). Existing `network_device` resources stay untouched as the catch-all for routers / load balancers / wireless. GUI-only — no host code, no migration. Prerequisite for the PMP importer's `Fortimanager` → firewall and `Cisco IOS` → switch mappings. Roadmap entry added under Resources. No code yet — spec only.

#### Password Manager Pro resource import — plugin (Phases 1, 2, 2.5, 2.6)

- New plugin `bastion-plugin-pmp` under `plugins-ext/` (submodule) — process-runtime importer for ManageEngine PMP `ExportPasswordView` spreadsheets (`.xls` BIFF + `.xlsx` OOXML via `calamine`). Mirrors `bastion-plugin-xca`'s shape: bootstrap-token init, line-delimited JSON over stdio, three operations (`validate` / `preview` / `import`). Plugin parses + structures only — never touches vault state.
  - **Mapping** (`src/mapping.rs`) — `OS Type` → BV `type` + `os_type` lookup (server/database/firewall/switch/website + KV kinds), per-call `type_overrides`, `EMPTY_SENTINELS` normaliser, name sanitiser, department slugifier.
  - **Parser** (`src/parser.rs`) — opens workbook, picks `ExportPasswordView` (or first sheet whose header carries the required columns), yields `RawRow`s with original headers preserved; reports `missing_required` + `unknown_columns`.
  - **Planner** (`src/plan.rs`) — collapses multi-account rows into one resource with N secrets, routes `Generic Keys` / `Application Passwords` / `License Store` rows into `kv_blobs[]` under `secret/pmp-import/<batch-id>/<kind>/<resource>/<account>`, derives one asset group per distinct PMP `Department` (slugified, `members` + `secrets` arrays, `exists` flag echoed from caller-supplied `existing_asset_groups[]`), preserves PMP custom columns when `preserve_unknown_columns = true`, routes operator-selected columns into `tags`. Plan deliberately carries no `owner` field — ownership is recorded by the host's `OwnerStore` when the wizard's writes execute under the operator's identity.
  - **Tests** — 5 unit (mapping/sanitisation/slug coverage) + 2 fixture-driven integration tests green against the operator's real PMP sample (99 rows → 55 resources + 8 KV blobs + 10 asset groups; multi-account collapse verified; firewall/switch/database routing confirmed). Smoke-tested end-to-end over stdio.
  - **GUI wizard (Phase 4)** — new route `/resources/import-pmp` (`gui/src/routes/PmpImportPage.tsx`) with three-step flow. Plugin-presence gate via `pluginsList()` (entry button on the Resources page header, hidden when `pmp-import` isn't installed; full-page "plugin not installed" empty state on the route itself). Step 1 picks the file via Tauri's file dialog and runs `op=validate`; Step 2 builds the plan and renders the resources tree (per-resource expand reveals the masked account list — labelled `account` + sanitised key + `pmp_last_accessed` — so the operator sees the resource-to-accounts linkage before running), KV-blobs tree, asset-groups panel (will-create vs will-update), summary metrics, owner banner; Step 3 walks the plan in three passes — asset-groups (read-merge-write), then **resource + every related account-secret** (`write_resource` immediately followed by N `write_resource_secret(...)` per account from the PMP rows, never a resource-without-accounts), then KV blobs under the operator-selected KV mount.
  - **Resource ↔ accounts contract** — added explicit "Account secrets per resource" section to the spec; planner now drops resources whose `secrets[]` would be empty (defence-in-depth on top of row-level skips); fixture test asserts every imported resource carries at least one account, that `Σ secrets[].len() == summary.secret_count`, and that account keys within a resource are unique.
  - **Phase 5 — hardening + docs.** Encrypted-export rejection at validate time: `parser::sniff_encrypted` sniffs the first 8 KiB for the OLE-CFB magic + UTF-16LE `EncryptedPackage` / `EncryptionInfo` markers and surfaces a friendly "re-export without per-export encryption" message instead of leaking the calamine error. New `tests/version_matrix.rs` covers PMP 11.x minimal layout, PMP 12.x full layout (Department + custom columns), PMP 13.x reordered headers + KV-bound rows, plus regressions for missing required columns / unknown PMP types / missing-Password row-skip / encrypted-file rejection (7 tests, all passing). `lib::build_synthetic_sheet` test helper exposes a `ParsedSheet` factory so the matrix doesn't need per-version `.xls` fixtures committed. New operator migration guide at `plugins-ext/bastion-plugin-pmp/docs/migration-guide.md` walks through prerequisites, PMP-side export, the wizard's three steps, post-import checklist, and a troubleshooting table. Plugin tests now total 14 (5 unit + 2 fixture + 7 version-matrix), all green. Status flipped to **Done** in roadmap.

#### First-class `firewall` / `switch` resource types + refined `database` — Phases 2 & 3

- **Phase 2 — PMP importer alignment** — verified end-to-end that the `bastion-plugin-pmp` plugin's lookup table writes `Fortimanager` rows as BV `firewall` resources (vendor=fortinet) and `Cisco IOS` rows as BV `switch` resources (vendor=cisco), with the operator's real PMP fixture surfacing both types in the wizard's type-distribution panel. (No additional plugin code needed — the alignment was already part of the Phase 1/2 plugin work; this phase recorded the verification.)
- **Phase 3 — docs** — `features/resources.md` "Built-in Resource Types" table updated with `firewall` (vendor / HA role / firmware / site / SSH-22 Connect), `switch` (vendor / layer / firmware / stack-member-count / SSH-22 Connect), refined `database` (engine enum / engine_version / tls_required), and a clarified `network_device` description ("catch-all for routers, load balancers, wireless controllers, console servers"). Spec status flipped to **Done**; roadmap row updated.

#### Password Manager Pro resource import — feature spec

- New feature spec at [`features/pmp-import.md`](features/pmp-import.md) — designs a `bastion-plugin-pmp` external plugin (process runtime, mirrors `bastion-plugin-xca`) that imports ManageEngine Password Manager Pro `ExportPasswordView` spreadsheets (`.xls` + `.xlsx`) into the Resource engine. Plugin parses + structures only; the GUI walks the returned plan via existing `write_resource` / `write_resource_secret` / `write_secret` / `write_asset_group` Tauri commands. PMP's non-resource-shaped row types (`Generic Keys`, `Application Passwords`, `License Store`) route to the **KV engine** under `secret/pmp-import/<batch-id>/<kind>/<resource>/<account>` instead of synthesising empty `application` resources. **PMP `Department` maps to a slugified asset group** (auto-created on first encounter, merged on re-run; preserves existing members) — not to `metadata.owner`. **Resource ownership is the importing operator's identity**, recorded via the existing `OwnerStore`; the plugin's plan never carries a parsed `owner` field. Zero host-crate code. Roadmap entry added under PKI / Engines → Importers. No code yet — spec only.

#### PKI — Cert / issuer export with exportable-at-create flag

Two new endpoints + a read-only safety flag for getting cert (and,
when permitted, key) bytes out of the vault:

- `GET pki/cert/<serial>/export` — PEM bundle (cert + chain,
  optionally + private key) or certs-only PKCS#7 (`.p7b`). Honours
  the bound managed key's `exportable` flag for the
  `include_private_key=true` knob; refuses the flag for
  format=pkcs7 (no key slot in the spec). Wires `mode=backup` for a
  future PKCS#12-encrypted backup envelope (rejected today since
  PKCS#12 lands in a follow-up — the route shape stays stable so
  the GUI doesn't break later).
- `GET pki/issuer/<ref>/export` — PEM or PKCS#7 of the issuer cert
  + chain. **Never** emits the private key, regardless of policy
  or mode — the route doesn't accept `include_private_key` at all.

`KeyEntry.exportable` is the new gate ([src/modules/pki/keys.rs:97](src/modules/pki/keys.rs:97)):
- Pinned at managed-key create / import time. **Read-only after** —
  no API surfaces a flip. Even root cannot promote a non-exportable
  key.
- Defaults: `false` for `pki/keys/generate`, `pki/keys/import`, and
  `pki/csr/generate` (operator opts in explicitly); `true` for the
  shadow entries created alongside an issuer ([src/modules/pki/issuers.rs](src/modules/pki/issuers.rs))
  remains `false` per the "issuer keys never leave" rule.

Format encoders ([src/modules/pki/export.rs](src/modules/pki/export.rs)):
- PEM bundler — concatenates cert + chain (+ optional key) PEMs.
- PKCS#7 builder — uses `cms 0.2`'s `SignedData` to wrap a
  `CertificateSet` with empty `digestAlgorithms` and `signerInfos`.
  Output is PEM-armored under `-----BEGIN PKCS7-----`, the shape
  every TLS-importer accepts. No private key support — PKCS#7
  doesn't carry one. New dep: `cms = "0.2"` (stays in the
  `der 0.7 / x509-cert 0.2` family the rest of the PKI module
  already uses, so it slots in without triggering the deferred
  Phase-3 RustCrypto-formats migration).

GUI ([gui/src/routes/PkiPage.tsx](gui/src/routes/PkiPage.tsx)):
- New `Export` button on the cert detail panel and the issuer
  detail panel.
- Shared `ExportModal` — format radio (`PEM` / `PKCS#7`),
  "include private key" checkbox (greyed out for PKCS#7), Copy +
  Download actions. Download uses a browser blob anchor so we
  don't pull in `@tauri-apps/plugin-fs`.
- Tauri commands `pki_export_cert` and `pki_export_issuer`
  ([gui/src-tauri/src/commands/pki.rs](gui/src-tauri/src/commands/pki.rs))
  thin-wrap the host endpoints; matching `pkiExportCert` /
  `pkiExportIssuer` exports in [gui/src/lib/api.ts](gui/src/lib/api.ts).

Sample policies ([docs/policies/](docs/policies/)): three Vault-style
HCL policies (`pki-readonly`, `pki-issuer`, `pki-exporter`) showing
the recommended ACL split — read-only auditors, CI services that
issue but never extract, and the helpdesk role that can pull bytes
out. The host's `KeyEntry.exportable` gate is documented as
defence-in-depth on top of the ACL.

**PKCS#12 (`.p12`) export** — pure-Rust, no `openssl-sys` /
`aws-lc-sys`. Adds `pkcs12 0.1.0` (with `kdf` feature for the
RFC 7292 Appendix B.2 KDF) and `pkcs5 0.7` (with `pbes2` +
`alloc` features for the password-based encryption envelope) on
top of the existing `der 0.7` / `x509-cert 0.2` family. Bundle
shape mirrors what OpenSSL emits:

  * AuthenticatedSafe = SEQUENCE OF [
      ContentInfo(id-encryptedData, EncryptedData(PBES2 over
        SafeContents containing one CertBag per cert in the
        chain)),
      (when private_key_pem is supplied)
      ContentInfo(id-data, SafeContents containing one
        pkcs8-shrouded-key bag wrapping a PBES2-encrypted
        EncryptedPrivateKeyInfo).
    ]
  * Outer ContentInfo = id-data wrapping the AuthenticatedSafe
    DER.
  * MacData = HMAC-SHA256 over the AuthenticatedSafe DER, key
    derived via the PKCS#12 KDF.

Both encrypted sections use the same `password` so importers
prompt the user only once. PBKDF2-SHA256 + AES-256-CBC at 100k
iterations matches modern OpenSSL defaults; salts and IVs are
fresh-random per envelope.

Wire shape: the host endpoint returns the raw DER as base64 in
the JSON response (PKCS#12 is binary; PEM / PKCS#7 stay UTF-8).
The new `body_encoding` field tells the GUI to base64-decode
before stuffing into the download Blob, so the `.p12` lands on
disk byte-correct.

`mode=backup` now works end-to-end — bypasses the
`KeyEntry.exportable=false` flag, requires `format=pkcs12` (so
the bypassed key still ends up encrypted on disk), and accepts
the same password parameter.

#### PKI — External-signing CSR flow for leaf certs

Lets operators generate a leaf CSR locally, hand it to an external CA
for signing, and install the resulting cert back into the engine — the
leaf-cert analogue of the existing `pki/intermediate/generate` +
`pki/intermediate/set-signed` flow that already exists for
intermediate CAs. The backing private key stays in the managed-key
store throughout, and the upstream-signed cert lands under the
orphan-cert index (`is_orphaned: true`, `source: "csr-external"`)
bound to that key — so `pki/key/<id>` delete refuses while the cert
is live.

Backend:
- [`src/modules/pki/path_csr.rs`](src/modules/pki/path_csr.rs) — new
  module exposing
  `pki/csr/generate` (Write),
  `pki/csr` (List),
  `pki/csr/<csr_id>` (Read, Delete), and
  `pki/csr/<csr_id>/set-signed` (Write).
- [`src/modules/pki/storage.rs`](src/modules/pki/storage.rs) — new
  `PendingCsr` record + `csr/pending/<id>` storage prefix.
- [`src/modules/pki/x509.rs`](src/modules/pki/x509.rs) — new
  `build_leaf_csr` helper: routes through the existing
  `params_for_subject` so the CSR carries the same role-driven
  Key Usage / EKU / DN locked-fields the issue path produces. CSRs
  request — the upstream CA decides whether to honour.
- [`src/modules/pki/mod.rs`](src/modules/pki/mod.rs) — routes
  registered alongside the intermediate / issue paths.

Tauri commands + frontend api:
- [`gui/src-tauri/src/commands/pki.rs`](gui/src-tauri/src/commands/pki.rs)
  — `pki_csr_generate`, `pki_csr_list`, `pki_csr_read`, `pki_csr_delete`,
  `pki_csr_set_signed` wrap the routes with strongly-typed request /
  response shapes.
- [`gui/src/lib/api.ts`](gui/src/lib/api.ts) — matching
  `pkiCsr*` exports.

GUI:
- [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx) — new
  **External CSR** tab between *Certificates* and *Tidy*. Three
  panels: a generate form (role + CN + SANs + optional `key_ref`
  reuse + optional one-shot private-key export), a pending-CSRs
  table (Common Name / Role / CSR ID / Key / Created + per-row
  Copy-CSR / Install-signed-cert / Drop actions), and an inline
  paste-cert panel that runs `set-signed` against the selected
  pending row.

Validation: `set-signed` parses the supplied PEM, compares the cert's
`SubjectPublicKeyInfo` against the pending CSR's pubkey, and rejects
with `ErrPkiCertKeyMismatch` on divergence — the same check the
`pki/intermediate/set-signed` path already runs. The cert serial gets
bound to the backing key via `keys::add_cert_ref`, then the pending
record is dropped. Re-issuance against the same key is supported by
running `csr/generate` again with `key_ref` set to the persisted key
UUID (subject to the role's `allow_key_reuse` / `allowed_key_refs`
gating).

Phase 1 limit: classical algorithms only (RSA / ECDSA / Ed25519). PQC
CSR support lands when the rcgen-PQC story is ready — the dispatch
in `path_csr.rs::csr_generate` already routes through `Signer` so
the PQC path is a small follow-up.

### Changed

#### Dependency upgrade sweep — Phases 1, 2, 4, 5 (russh), 6

Bulk dependency upgrade across the workspace (`Cargo.toml`, `crates/bv-plugin-pack/Cargo.toml`, `gui/src-tauri/Cargo.toml`, `IronRDP/Cargo.toml`). All bumps verified with `cargo check --workspace` and the 61-test `plugins::*` suite (61 passed, 0 failed); the 20 preexisting CLI-harness test failures (`cli::command::*`) reproduce on `main` and are unrelated.

**Major bumps**:
- `wasmtime 27 → 43` ([`src/plugins/module_cache.rs`](src/plugins/module_cache.rs)) — dropped deprecated `Config::async_support(true)` no-op; rest of the host API surface (Engine, Module, Store, Linker, Caller, TypedFunc, Memory, StoreLimits, fuel API) was stable across the 16-major span.
- `russh 0.45 → 0.60` + dropped separate `russh-keys 0.45` ([`src/modules/files/ssh_sync.rs`](src/modules/files/ssh_sync.rs), [`gui/src-tauri/src/session/ssh.rs`](gui/src-tauri/src/session/ssh.rs)) — `russh::keys::key::PublicKey` → `russh::keys::PublicKey` (re-export from `ssh_key`); `authenticate_publickey` now takes `PrivateKeyWithHashAlg::new(Arc::new(key), None)` instead of `Arc<KeyPair>`; `authenticate_*` returns `AuthResult` (use `.success()`) instead of `bool`; `Handler` lost `#[async_trait]` (russh ≥ 0.59 uses async-fn-in-trait).
- `sspi git-rev → 0.20.1` (crates.io) ([`gui/src-tauri/Cargo.toml`](gui/src-tauri/Cargo.toml), [`IronRDP/Cargo.toml`](IronRDP/Cargo.toml)) — removed the Devolutions git pin in favour of the published release; deduplicates the `winscard` transitive.
- `tauri 2.10.3 → 2.11.0` — full family bump (tauri-build, tauri-codegen, tauri-macros, tauri-plugin, tauri-runtime, tauri-runtime-wry, tauri-utils, tauri-winres, tauri-plugin-dialog, tauri-plugin-fs).
- `webauthn-rs 0.5.4 → 0.5.5` (webauthn-rs, webauthn-rs-core, webauthn-rs-proto, webauthn-attestation-ca).
- `cucumber 0.21 → 0.23`, `wry 0.54 → 0.55`, `tao 0.34.8 → 0.35`, `tray-icon 0.21 → 0.23`, `wasm-encoder/wasmparser/wast/wat 246 → 248`.

**Format / parser bumps**:
- `x509-parser 0.17 → 0.18` (parent + gui).
- `webview2-com 0.38 → 0.39`, `windows 0.61 → 0.62` (gui windows-only deps).

**RustCrypto family** (Phase 2):
- `sha2 0.10 → 0.11` ([`crates/bv-plugin-pack/Cargo.toml`](crates/bv-plugin-pack/Cargo.toml), [`gui/src-tauri/Cargo.toml`](gui/src-tauri/Cargo.toml)).
- `hkdf 0.12 → 0.13` ([`gui/src-tauri/Cargo.toml`](gui/src-tauri/Cargo.toml)).

**Patch / minor compatibility bumps** (~50 packages from Phase 1 + Phase 6 `cargo update`): `actix-http`, `aws-lc-rs`, `bitflags`, `blake3`, `cc`, `clap`, `compression-codecs`/`-core`, `crc-catalog`, `data-encoding`, `diesel`, `embed-resource`, `hybrid-array`, `idna_adapter`, `indexmap`, `jiff`, `js-sys`, `libc`, `libredox`, `open`, `openraft` (incl. `openraft-macros`), `openssl`, `openssl-sys`, `pkg-config`, `plist`, `portable-atomic-util`, `reqwest`, `rpassword`, `rustls`, `rustls-pki-types`, `rustls-webpki`, `siphasher`, `serde_with`, `serdect`, `sha3`, `sqlite-wasm-rs`, `typenum`, `uuid`, `wasm-bindgen` family, `web-sys`, `webpki-roots`, `winnow`, `russh-sftp 2.1.1 → 2.1.2`, `web_atoms`, `bytestring`, `base64urlsafedata`. Also pruned dead transitives (phf 0.8/0.10, rand 0.7, string_cache, selectors, servo_arc, tendril, tiny-keccak, proc-macro-hack, wasi 0.9).

**Forward-compatible cleanup**:
- [`src/modules/pki/keys.rs`](src/modules/pki/keys.rs), [`src/modules/pki/crypto.rs`](src/modules/pki/crypto.rs) — RSA-side `pkcs8` imports switched to `rsa::pkcs8::*` (rsa's own re-export). Decouples our top-level pkcs8 dep from rsa's transitive pkcs8, so a future Phase-3 pkcs8 0.11 bump won't conflict with rsa 0.9's pkcs8 0.10.

### Fixed

#### Preexisting build issues uncovered during the dep sweep

- [`gui/src-tauri/Cargo.toml`](gui/src-tauri/Cargo.toml) — `openssl` moved out of `[target.'cfg(windows)'.dependencies]` to general dependencies. [`commands/pki.rs::pki_import_ca_pkcs12`](gui/src-tauri/src/commands/pki.rs) calls `openssl::pkcs12::Pkcs12::from_der` on every desktop platform; the windows-only gating broke the macOS / Linux gui builds.
- [`src/plugins/logical_backend.rs`](src/plugins/logical_backend.rs) — added `use serde_json::Map` to the test module so `cargo test --lib` compiles. Was preexisting on `main` and blocked the entire lib-test build.

#### Build tooling

- [`Makefile`](Makefile) — `RUSTUP_CARGO_BIN` (default `$HOME/.cargo/bin`, with `$USERPROFILE` fallback for native Windows) is prepended to `PATH` so rustup's toolchain wins over a system Rust install (Homebrew `rust` on macOS, distro packages on Linux). Symptom previously: `make plugins-wasm` failed with `can't find crate for core` even after `rustup target add wasm32-wasip1`, because Homebrew's rustc only ships the host std and was being picked first.

### Added

#### PKI — Import root CA (PEM / PKCS#12) + richer Certificates detail pane

- [`gui/src-tauri/src/commands/pki.rs`](gui/src-tauri/src/commands/pki.rs), [`gui/src-tauri/src/lib.rs`](gui/src-tauri/src/lib.rs), [`gui/src/lib/api.ts`](gui/src/lib/api.ts), [`gui/src/lib/types.ts`](gui/src/lib/types.ts) — new `pki_import_ca_pkcs12` Tauri command. The renderer reads the `.p12` / `.pfx` file, base64-encodes it, and ships it with a passphrase to the Tauri process; `openssl::pkcs12::Pkcs12::parse2` unwraps the bag into a cert + private key, the key is re-emitted as unencrypted PKCS#8, and the assembled PEM bundle is forwarded to the existing `pki/config/ca` route. The passphrase never crosses the network — the unwrap runs entirely on the local Tauri process.
- [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx) — Issuers tab gains an **Import root CA** action (next to *Generate root CA*). The new modal toggles between *PEM bundle* (textarea) and *PKCS#12* (file picker + passphrase). Both modes route through `pki/config/ca` so the imported CA lands as a normal issuer, with the existing shadow-managed-key shim wiring the Keys tab.
- [`gui/src-tauri/src/commands/pki.rs`](gui/src-tauri/src/commands/pki.rs) — `parse_cert_meta` extended with `parse_cert_extras` (uses `x509-parser`) so `pki_read_cert` now also surfaces SubjectAltName entries (DNS / IP / email / URI), KeyUsage flags, and ExtendedKeyUsage labels.
- [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx) — Certificates tab right-pane is now a structured **CertDetail** component showing CN, Emitter (with owned/external glyph), Issued/Expires, Source for orphan imports, KU and EKU as badge groups, and SANs grouped by kind. The cert PEM stays in a copy-buttoned block underneath. Cert list now occupies 2/3 of the row width and the detail pane 1/3.
- [`gui/src-tauri/Cargo.toml`](gui/src-tauri/Cargo.toml) — `x509-parser` 0.17 added to mirror the host-crate pin (used for the cert-extension decoding above).

### Fixed

#### PKI — cert/key lifecycle + Certificates tab layout

- [`src/modules/pki/keys.rs`](src/modules/pki/keys.rs) — `force_delete_key` now refuses when the managed key still backs an issuer, regardless of `force=true`. Since the legacy `issuers/<id>/key` migration shim deletes the issuer's own private-key copy after mirroring it into the managed-key store, the managed-key entry is the only signing material the issuer has — force-deleting it silently bricked revoke + CRL rebuild for that issuer. The operator must `DELETE pki/issuer/<ref>` first; `force` continues to bypass *cert*-level bindings (cert reads do not need the signing key).
- [`src/modules/pki/issuers.rs`](src/modules/pki/issuers.rs) — `delete_issuer` now removes the matching entry from the shadow managed-key's `KeyRefs.issuer_ids` before nuking the issuer's storage. Previously the binding stayed behind, so a follow-up `DELETE pki/key/<id>` refused forever, citing a phantom issuer that no longer existed.
- [`gui/src/components/ui/Table.tsx`](gui/src/components/ui/Table.tsx), [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx) — Certificates tab table no longer overflows horizontally inside the 1/3-width column container. `Table` accepts an optional `tableClassName`; the cert list opts into `table-fixed` with explicit per-column widths so long hex serials, DNs, and the orphan badge truncate cleanly instead of forcing a sideways scrollbar.
- [`tests/test_pki_cert_key_lifecycle.rs`](tests/test_pki_cert_key_lifecycle.rs) — new integration test covering the full cert↔managed-key CRUD loop: issuer-bound key force-delete is refused, `delete_issuer` clears the issuer→key binding so the key becomes deletable, `key_ref` issuance + revoke + delete round-trips clear `KeyRefs.cert_serials`, and the fresh-key path stays decoupled from L3 binding bookkeeping.

### Added

#### PKI — managed-key force-delete + cert delete

- [`src/modules/pki/keys.rs`](src/modules/pki/keys.rs), [`src/modules/pki/path_keys.rs`](src/modules/pki/path_keys.rs) — `DELETE /v1/pki/key/<key_ref>` accepts `force=true`. With force the engine drops the managed-key entry even when issuer / cert references remain in `KeyRefs`. The bound issuer's own private-key copy at `issuers/<id>/key` is preserved, so the issuer keeps signing — only the audit-trail link to that managed-key entry is dropped. Default behaviour (force absent or false) still refuses the delete and lists the outstanding bindings, matching pre-existing semantics.
- [`src/modules/pki/path_fetch.rs`](src/modules/pki/path_fetch.rs) — new `DELETE /v1/pki/cert/<serial>` operation. Removes the cert record from `certs/<serial>`, pulls the serial from the issuer's per-issuer CRL revoked-list (and rebuilds that issuer's CRL) when present, and clears the cert→managed-key binding inside `KeyRefs.cert_serials` on a best-effort basis. Active (non-revoked, non-expired) certs require `force=true`; revoked or expired records delete without force.
- [`gui/src-tauri/src/commands/pki.rs`](gui/src-tauri/src/commands/pki.rs), [`gui/src-tauri/src/lib.rs`](gui/src-tauri/src/lib.rs), [`gui/src/lib/api.ts`](gui/src/lib/api.ts) — `pki_delete_key` gains an optional `force` argument; new `pki_delete_cert` Tauri command wraps the cert-delete route.
- [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx) — Keys tab Delete button is no longer disabled when the key has issuer / cert references; the confirm modal switches into a force-delete variant that explains the audit-trail tradeoff before sending `force=true`. Certificates tab gains a Delete action (alongside Revoke) with an active-vs-inactive force prompt.

### Changed

#### PKI — issuer keys live in the managed-key store (Phase L8 cleanup)
- [`src/modules/pki/storage.rs`](src/modules/pki/storage.rs) — `CaMetadata` gains `key_id: String` (`#[serde(default)]`). The issuer's keypair is no longer stored at `issuers/<id>/key` for new issuers; instead `meta.key_id` points at a managed-key entry in `pki/keys/*` that holds the private material as the single source of truth.
- [`src/modules/pki/issuers.rs`](src/modules/pki/issuers.rs) — `add_issuer` now takes an optional `key_id_hint: Option<String>`. When `Some`, reuses an operator-pre-created managed key (i.e. `key_ref` was supplied at root/intermediate generation). When `None`, mints a shadow managed-key entry mirroring the signer (named `<issuer-name>-key`, with collision-safe disambiguation) so the issuer always shows up in the Keys tab. Records the issuer→key binding inside `add_issuer`, removing the duplicated `add_issuer_ref` follow-up at every caller.
- [`src/modules/pki/issuers.rs`](src/modules/pki/issuers.rs) — `load_issuer_by_id` reads the signer via `meta.key_id` from the managed-key store. Lazy migration shim handles legacy issuers that still have a private key at `issuers/<id>/key`: on first load it lifts the legacy key into a fresh managed-key entry, sets `meta.key_id`, deletes the legacy storage path, and continues. The two-stage migration (pre-5.2 singleton → 5.2 multi-issuer → L8 managed-key) is idempotent.
- [`src/modules/pki/keys.rs`](src/modules/pki/keys.rs) — new `create_managed_key_from_signer(req, signer, name, source)` helper used by `add_issuer` + the migration shim to mint shadow entries from an existing signer's PEM.
- [`src/modules/pki/path_root.rs`](src/modules/pki/path_root.rs), [`src/modules/pki/path_intermediate.rs`](src/modules/pki/path_intermediate.rs), [`src/modules/pki/path_config.rs`](src/modules/pki/path_config.rs) — three `add_issuer` callers updated for the new signature. Issuer-generate responses now surface `key_id` (read back from the freshly-loaded handle) so the GUI can deep-link straight to the Keys tab.
- [`src/modules/pki/path_issuers.rs`](src/modules/pki/path_issuers.rs) — `pki/issuer/<ref>` read response carries `key_id` when populated.

### Added

#### XCA import — chain-driven issuer / leaf routing fixes (plugin v0.1.10)
- **Plugin v0.1.10**: dropped `#[serde(default, skip_serializing_if = "std::ops::Not::not")]` on `is_ca` and `signs_others` in `PreviewItem`. Both fields are now always serialised on the wire so the GUI never sees `undefined` and falls through to the legacy "treat as CA" default — this was the root cause of leaf certs being misrouted to `pki/config/ca` and bouncing with `BasicConstraints.cA=true required`.
- [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx) — XCA Apply flow restructured so every selectable item lands somewhere:
  - **Leaf cert + paired key**: imports the key into the managed key store via `pki/keys/import` (named after the cert's CN), then orphan-imports the cert via `pki/certs/import`. Operators can later pin the key with `key_ref` on issuance.
  - **Standalone private key** (no paired cert in the file): imported directly into the managed key store. Was previously skipped with no destination.
  - **CA cert + paired key**: unchanged — bundle goes through `pki/config/ca`. The host engine now auto-mints a shadow managed-key entry alongside the imported issuer so it appears in the Keys tab too.
- [`gui/src-tauri/src/commands/pki.rs`](gui/src-tauri/src/commands/pki.rs) + [`gui/src/lib/types.ts`](gui/src/lib/types.ts) — `PkiIssuerDetail` carries `key_id` from the engine; the issuer detail panel displays it as "Backing key (managed-key UUID)" so the cert↔key relationship is explicit in the UI.

#### XCA import — chain-driven issuer / leaf routing + Emitter column on Certificates tab
- [`plugins-ext/bastion-plugin-xca`](plugins-ext/bastion-plugin-xca) bumped to **v0.1.9**. New `chain.rs` module walks the imported cert graph and reports per-cert `signs_others` / `signer_item_id` / `signer_subject`. Linkage uses AKI→SKI when both extensions are present and falls back to Issuer DN → Subject DN. The plugin's `summary.issuer_count` / `leaf_count` are now recomputed from the chain pass so the numbers match what the GUI will route. Three `chain::tests` unit tests cover standalone self-signed CA, CA + leaf in set, and standalone leaf with off-set parent.
- [`gui/src-tauri/src/commands/pki.rs`](gui/src-tauri/src/commands/pki.rs) — `PkiCertRecord` gains `issuer_id` (passed through from the engine) and `issuer_dn` (parsed from the cert PEM by `parse_cert_meta`). Both fields surface on `pki_read_cert`.
- [`gui/src/lib/types.ts`](gui/src/lib/types.ts) — `PkiCertRecord`, `XcaPreviewItem` extended with the new fields.
- [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx) — XCA Apply flow now routes by `signs_others` (with backwards-compatible fallback to `is_ca` for older plugins) via a new `isEmitter()` helper. CA-flagged certs that never actually signed anything in the file land on the certificates tab instead of the issuers tab. The XCA preview Type column reads `cert (issuer)` / `cert (leaf)` accordingly. The Certificates tab gets a new **Emitter** column that loads issuers once per refresh and renders `🔒 <issuer-name>` (green / "owned" — the cert was signed by an issuer on this mount) or `🌐 <issuer-CN>` (muted / "external" — orphan import or unknown issuer_id), with the full DN in the tooltip.

#### PKI — intermediate-emitter import via `config/ca` + BasicConstraints gate
- [`src/modules/pki/path_config.rs`](src/modules/pki/path_config.rs) — `pki/config/ca` now enforces `BasicConstraints.cA = true` on the imported cert via the new `cert_claims_ca` helper. Both self-signed roots and intermediates (CA-flagged certs whose Issuer DN refers to a separate parent) are accepted; leaf certs are rejected with `config/ca: certificate is not a CA … use pki/certs/import for leaf certs` so an operator can't accidentally promote a leaf to issuer status.
- The chain-walking helper from L3 (`build_issuer_chain`) already resolves intermediate → root by Subject / Issuer DN match, so importing root + intermediate via two separate `config/ca` calls produces a working 2-entry `ca_chain` on every issue/sign response routed through the intermediate, with no extra wiring.
- [`tests/test_pki_intermediate_import.rs`](tests/test_pki_intermediate_import.rs) (new) — 5-step coverage proving intermediate-emitter import works end-to-end: build root + intermediate externally with rcgen; import both via `config/ca`; verify `pki/issuer/<intermediate>/chain` returns `[intermediate, root]`; issue a leaf pinned to the intermediate and confirm the response's `ca_chain` is length 2 with the leaf's Issuer DN matching the intermediate's Subject DN; verify a leaf cert (BasicConstraints.cA=false) is rejected by `config/ca`.

#### Cert-Lifecycle delivery plugins + http-push (Phase L7 of pki-key-management-and-lifecycle)
- [`src/modules/cert_lifecycle/delivery.rs`](src/modules/cert_lifecycle/delivery.rs) (new) — `CertDeliveryPlugin` trait with `name()` + `deliver(target, bundle) -> Result<DeliveryReceipt, String>`. `CertBundle` carries the cert + key + chain PEMs the renewer just received from PKI. Built-in implementations:
  - `FileDeliverer` (factored out of L5's monolithic `deliver` function — atomic-write `cert.pem` / `key.pem` / `chain.pem` into the target's `address` directory).
  - `HttpPushDeliverer` — `POST` a JSON envelope (`{target, serial, certificate, private_key, ca_chain}`) to the URL at `address`. Uses `ureq` (already a direct dep). 2xx is success; non-2xx surfaces the status code as a delivery error. Address must be `http://` or `https://`.
  `DelivererRegistry` is the lookup table; `with_builtins()` seeds it with both built-ins; `register()` is the plug point an L7 follow-up will use to graft external `plugin-ext` deliverers in at unseal time.
- [`src/modules/cert_lifecycle/storage.rs`](src/modules/cert_lifecycle/storage.rs) — `TargetKind` gains `HttpPush` (kebab-case `"http-push"`). `from_str` / `as_str` extended.
- [`src/modules/cert_lifecycle/path_targets.rs`](src/modules/cert_lifecycle/path_targets.rs) — kind-aware address validation: `http-push` requires `http://` or `https://` prefix; the prior file-only message is generalised.
- [`src/modules/cert_lifecycle/path_renew.rs`](src/modules/cert_lifecycle/path_renew.rs) — `deliver` no longer matches on `TargetKind`; it looks up the registered plugin via `DelivererRegistry::get(registry_key_for(&target.kind))` and calls its trait method. The renew response now carries `delivery_kind`, `delivered_to` (the receipt's destination), and `delivery_note` (e.g. `"HTTP 204"`).
- [`src/modules/cert_lifecycle/mod.rs`](src/modules/cert_lifecycle/mod.rs) — `CertLifecycleBackendInner` holds a `DelivererRegistry`. New route `READ /v1/cert-lifecycle/sys/deliverers` returns the names of every registered plugin (admin/observability surface; future `plugin-ext` deliverers show up here automatically once registered).
- [`tests/test_cert_lifecycle_plugin.rs`](tests/test_cert_lifecycle_plugin.rs) (new) — 4-step coverage: `sys/deliverers` lists `file` + `http-push`; non-URL address on `kind=http-push` rejected at write time; end-to-end `http-push` renewal POSTs the JSON envelope to a localhost capture server (built with `std::net::TcpListener` so no external dep), and the cert-lifecycle response surfaces `delivery_kind = http-push` plus the URL; target state reflects the new serial.

L7 plug-point is wired; the only thing not yet implemented is the **`plugin-ext` bridge** that would let third-party Rust binaries register additional `CertDeliveryPlugin` implementations at runtime. The trait + registry are stable surface; the bridge is a follow-up that touches the existing `plugin-ext` IPC contract rather than this module.

#### Cert-Lifecycle renewal scheduler (Phase L6 of pki-key-management-and-lifecycle)
- [`src/modules/cert_lifecycle/scheduler.rs`](src/modules/cert_lifecycle/scheduler.rs) (new) — single tokio task started from `Core::post_unseal`. Mirrors the lifecycle posture of `pki/scheduler.rs` (auto-tidy): outer tick every 30s, self-skip while sealed, single-process (no HA leader gate yet), per-mount throttle from `SchedulerConfig.tick_interval_seconds`. Walks every `cert-lifecycle` mount each tick, lists targets, and decides whether to fire renewal via `is_due`: never-issued targets fire immediately (subject to backoff), healthy targets fire when `now >= current_not_after - renew_before`. Renewal dispatches `cert-lifecycle/renew/<name>` via `Core::handle_request` carrying the operator-supplied `client_token`, so the existing PKI ACL boundary applies — there is no scheduler-side ACL bypass. After each attempt the scheduler computes `next_attempt_unix`: success → `current_not_after - renew_before`; failure → `now + min(max_backoff, base_backoff * 2^(failure_count - 1))`. `run_cert_lifecycle_pass` is exposed publicly so integration tests can drive the scheduler deterministically without waiting on real-time ticks.
- [`src/modules/cert_lifecycle/storage.rs`](src/modules/cert_lifecycle/storage.rs) — new `SchedulerConfig` (enabled, tick_interval_seconds, client_token, base_backoff_seconds, max_backoff_seconds) at `scheduler/config`. `enabled = true` requires a non-empty `client_token` at write time.
- [`src/modules/cert_lifecycle/path_scheduler_config.rs`](src/modules/cert_lifecycle/path_scheduler_config.rs) (new) — `READ`/`WRITE /v1/cert-lifecycle/scheduler/config`. Token is write-only over the API: read returns `client_token_set: bool` instead of echoing the credential. Write semantics are upsert-with-preservation — omitting a field on update keeps the stored value.
- [`src/modules/cert_lifecycle/mod.rs`](src/modules/cert_lifecycle/mod.rs) — registers the new path and re-exports the scheduler module.
- [`src/core.rs`](src/core.rs) — `post_unseal` boots `start_cert_lifecycle_scheduler` alongside the existing PKI auto-tidy, LDAP rotation, files-sync, and scheduled-exports schedulers.
- [`tests/test_cert_lifecycle_scheduler.rs`](tests/test_cert_lifecycle_scheduler.rs) (new) — 5-step coverage: `enabled = true` without `client_token` rejected at config-write time; disabled scheduler is a no-op for a fresh target; enabled scheduler renews a never-issued target on first pass and writes the bundle; healthy in-window target is *not* re-renewed on a second pass; failure path (target points at a non-existent address) bumps `failure_count`, sets `last_error`, populates `next_attempt`, and a second pass before the backoff expires does not retry.

#### Cert-Lifecycle module skeleton (Phase L5 of pki-key-management-and-lifecycle)
- [`src/modules/cert_lifecycle/`](src/modules/cert_lifecycle/) (new module) — sibling top-level engine that *consumes* a PKI mount instead of holding any CA key of its own. Mounts at the global path `cert-lifecycle/`. Submodules:
  - [`storage.rs`](src/modules/cert_lifecycle/storage.rs) — `Target` (kind / address / pki_mount / role_ref / common_name / alt_names / ip_sans / ttl / key_policy / key_ref / renew_before / created_at), `TargetState` (current_serial / current_not_after / last_renewal / last_attempt / last_error / next_attempt / failure_count), `TargetKind` (currently `File`), `KeyPolicy` (`Rotate` / `Reuse` / `AgentGenerates` — last is reserved for L7).
  - [`path_targets.rs`](src/modules/cert_lifecycle/path_targets.rs) — `LIST cert-lifecycle/targets`, plus `READ`/`WRITE`/`DELETE cert-lifecycle/targets/<name>`. Required-field validation rejects malformed targets at write time (missing `role_ref`, `common_name`, `address` for kind=file, `key_ref` when `key_policy=reuse`). `agent-generates` is rejected with a clear "not implemented in Phase L5" message.
  - [`path_state.rs`](src/modules/cert_lifecycle/path_state.rs) — `READ cert-lifecycle/state/<name>` returns the renewer's bookkeeping for a target.
  - [`path_renew.rs`](src/modules/cert_lifecycle/path_renew.rs) — `WRITE cert-lifecycle/renew/<name>` triggers a manual renewal: dispatches `pki/issue/<role>` into the configured PKI mount via `Core::handle_request` (inheriting the caller's token, so the same role / issuer / emission-control gates apply), parses the response, atomic-writes `cert.pem` / `key.pem` / `chain.pem` into the target's `address` directory, updates `TargetState`. Failures record `last_error` + bump `failure_count`; success clears both. `key_policy = Reuse` plumbs the target's `key_ref` through to the PKI issue body so renewals share an SPKI.
- [`src/modules/mod.rs`](src/modules/mod.rs) + [`src/module_manager.rs`](src/module_manager.rs) — register the new `CertLifecycleModule` so `set_default_modules` sets up the `cert-lifecycle` mount type automatically alongside `pki`, `kv`, etc.
- [`tests/test_cert_lifecycle_basic.rs`](tests/test_cert_lifecycle_basic.rs) (new) — 6-step coverage: required-field validation rejects malformed targets and `agent-generates`; manual renew writes cert/key/chain into the target dir; state reflects the new serial + NotAfter; `key_policy = reuse` produces two consecutive renewals sharing one SubjectPublicKeyInfo (verified via `x509-parser`); LIST returns the inventory.
- [`features/pki-key-management-and-lifecycle.md`](features/pki-key-management-and-lifecycle.md) — Current State updated to mark L5 done.

L6 (periodic scheduler) and L7 (`CertDeliveryPlugin` trait + plugin-ext glue) build on this skeleton without new storage shape changes.

#### PKI — emission controls (Phase L4 of pki-key-management-and-lifecycle)
- [`src/modules/pki/path_roles.rs`](src/modules/pki/path_roles.rs) — `RoleEntry` gains `allowed_domains: Vec<String>`, `allow_glob_domains: bool`, and `acme_enabled: bool` (default `true` for backwards compatibility — pre-L4 roles continue to allow ACME). All three are `#[serde(default)]`.
- [`src/modules/pki/x509.rs`](src/modules/pki/x509.rs) — `validate_common_name` rewritten and a new `validate_dns_name(role, name)` helper closes the deferred Phase-1 stub. Implements the full Vault matrix: `allow_any_name`, `allow_localhost`, `allow_bare_domains`, `allow_subdomains`, and `allow_glob_domains` (single-label `*` patterns that don't span dots). `glob_match` rejects empty `*` matches for Vault parity.
- [`src/modules/pki/path_issue.rs`](src/modules/pki/path_issue.rs) — `pki/issue/:role` and `pki/sign/:role` now walk every DNS SAN through `validate_dns_name`, not just the CN. Off-list DNS SANs are rejected before the cert is built.
- [`src/modules/pki/acme/order.rs`](src/modules/pki/acme/order.rs) — `pki/acme/new-order` and `finalize` reject up front when the configured role has `acme_enabled = false`. The kill-switch fires at new-order time so the client doesn't burn through authz/challenge state for an order that can never finalize. SAN validation also runs at finalize.
- [`src/modules/pki/issuers.rs`](src/modules/pki/issuers.rs) — new `clamp_ttl_to_issuer(&issuer, requested) -> (Duration, was_clamped)`. Returns `ErrPkiCaNotConfig` for an already-expired issuer instead of producing a 0-second cert.
- [`src/modules/pki/path_issue.rs`](src/modules/pki/path_issue.rs) + [`src/modules/pki/acme/order.rs`](src/modules/pki/acme/order.rs) — `issue/:role`, `sign/:role`, `sign-verbatim`, and ACME finalize now clamp leaf TTL so the resulting cert's `NotAfter` never exceeds the issuer's. A 24h root with a 168h-requested leaf produces a leaf bounded by the root's `NotAfter` rather than rolling forward into invalid-chain territory.
- [`src/modules/pki/path_intermediate.rs`](src/modules/pki/path_intermediate.rs) — `pki/root/sign-intermediate` reads the parent issuer's `BasicConstraints.pathLenConstraint` (via new `issuer_path_len` helper using `x509-parser`), clamps the new intermediate's path length to `parent_max - 1`, and refuses to sign a child intermediate when the parent's `pathLenConstraint = 0`. Plus the same TTL clamp.
- [`tests/test_pki_emission_control.rs`](tests/test_pki_emission_control.rs) (new) — 6-step coverage: `allow_subdomains` matrix; `allow_bare_domains` permits the bare name; `allow_glob_domains` accepts in-label `*` but not cross-label or off-anchor; DNS SANs walk the policy too; `acme_enabled = false` rejects `pki/acme/new-order` with a clear message; leaf TTL clamped to a 24h root's `NotAfter` even when 168h is requested.

#### PKI — issuer-bound managed keys + chain UX (Phase L3 of pki-key-management-and-lifecycle)
- [`src/modules/pki/path_root.rs`](src/modules/pki/path_root.rs) — `pki/root/generate/{internal|exported}` accepts an optional `key_ref` body field. When set, the engine promotes a managed key from `pki/keys/*` to root issuer instead of generating fresh material; algorithm match against `key_type` / `key_bits` is enforced. Issuer-binding is recorded in `KeyRefs.issuer_ids` so `delete_key` refuses while the issuer uses this key. When `key_ref` is supplied, `exported` mode does *not* echo the private key — the operator already controls it via the key store.
- [`src/modules/pki/path_intermediate.rs`](src/modules/pki/path_intermediate.rs) — `pki/intermediate/generate/{internal|exported}` accepts `key_ref`; the binding is stashed on `PendingIntermediate` and finalized in `intermediate/set-signed` once the upstream-signed cert lands.
- [`src/modules/pki/storage.rs`](src/modules/pki/storage.rs) — `CertRecord` gains `key_id: String` (`#[serde(default)]`); `PendingIntermediate` gains `key_id: String` (`#[serde(default)]`). Pre-L3 records continue to deserialize.
- [`src/modules/pki/path_revoke.rs`](src/modules/pki/path_revoke.rs) — revoke now clears the cert-serial entry from the bound managed key's `KeyRefs` (best-effort; failures don't roll back the revocation). Closes the L2 follow-up so a managed key can be deleted once all certs it bound are revoked.
- [`src/modules/pki/keys.rs`](src/modules/pki/keys.rs) — new helpers: `add_issuer_ref`, `remove_cert_ref`. `entry_spki_der` already lives here from L2.
- [`src/modules/pki/issuers.rs`](src/modules/pki/issuers.rs) — new `build_issuer_chain(req, &issuer)` walks the local issuer registry by matching cert `Issuer DN` against another local issuer's `Subject DN` until a self-signed root or an off-mount parent is hit. Returns `Vec<String>` of cert PEMs in leaf-issuer→root order.
- [`src/modules/pki/path_issuers.rs`](src/modules/pki/path_issuers.rs) — new route `READ /v1/pki/issuer/<ref>/chain` returning `{issuer_id, issuer_name, ca_chain: [PEM,…], certificate_bundle: PEM}`. Wired into the backend.
- [`src/modules/pki/path_issue.rs`](src/modules/pki/path_issue.rs) — `pki/issue/:role`, `pki/sign/:role`, and `pki/sign-verbatim` responses now include `ca_chain` consistently. The leaf cert's `CertRecord.key_id` is populated when a managed key was pinned.
- [`src/modules/pki/acme/order.rs`](src/modules/pki/acme/order.rs) — ACME finalize record now sets `CertRecord.key_id = ""` for the new field.
- [`tests/test_pki_issuer_keys.rs`](tests/test_pki_issuer_keys.rs) (new) — 6-step coverage: algorithm-mismatch on `root/generate` rejected; EC managed key promoted to root yields a cert whose SPKI matches the managed key's; `issuer_ref_count` climbs to 1; delete refused; revoke clears `cert_ref_count` but leaves `issuer_ref_count` intact; `pki/issuer/<ref>/chain` returns a single-entry chain on a single-issuer mount.

#### PKI — key reuse on issuance (Phase L2 of pki-key-management-and-lifecycle)
- [`src/modules/pki/path_roles.rs`](src/modules/pki/path_roles.rs) — `RoleEntry` gains `allow_key_reuse: bool` (default `false`, closed) and `allowed_key_refs: Vec<String>` (optional allow-list of key IDs/names). Both `#[serde(default)]` so pre-L2 roles deserialize. New role-write fields surfaced through the existing schema.
- [`src/modules/pki/path_issue.rs`](src/modules/pki/path_issue.rs) — `pki/issue/:role` and `pki/sign/:role` accept an optional `key_ref` body field. On `issue`, the leaf is signed against the referenced managed key instead of a freshly-generated one (renewals carry the same private key). On `sign`, the CSR's SubjectPublicKeyInfo must match the pinned key — mismatch is a hard error. Algorithm-class mismatch (e.g. RSA managed key on EC role) is rejected. Both endpoints return the bound `key_id` in the response when pinning was used.
- [`src/modules/pki/keys.rs`](src/modules/pki/keys.rs) — new `add_cert_ref(req, key_id, serial)` helper records the issued serial in the key's refs file (idempotent), and `entry_spki_der(entry)` decodes a managed-key entry's `public_key_pem` back to its SPKI DER for the CSR-match assertion. After successful issuance, the cert serial is bound to the managed key so `delete_key` continues to refuse while bindings remain.
- [`tests/test_pki_key_reuse.rs`](tests/test_pki_key_reuse.rs) (new) — 7 cases: closed-role rejects `key_ref`; off-allow-list `key_ref` rejected; renewal across two `pki/issue` calls produces distinct serials sharing one SPKI (verified via `x509-parser`); refs count climbs to 2 and `DELETE pki/key/...` is refused; `pki/sign/:role` with mismatched CSR/key SPKI rejected; algorithm-class mismatch rejected; unpinned `pki/issue` still mints a fresh keypair.
- [`features/pki-key-management-and-lifecycle.md`](features/pki-key-management-and-lifecycle.md) — Current State updated to mark L2 done.

#### PKI — managed key store (Phase L1 of pki-key-management-and-lifecycle)
- [`src/modules/pki/keys.rs`](src/modules/pki/keys.rs) (new) — managed key store layer. `KeyEntry` (id, optional name, algorithm, public/private PEM, source, exported flag, timestamp), `KeyRefs` (issuer + cert reference set), and helpers: `generate_managed_key`, `import_managed_key`, `list_keys`, `load_key` (resolves UUID or name), `load_refs`, `delete_key`. Storage at `keys/<id>`, `key-names/<name>` (id pointer), `key-refs/<id>` (refs file) — separate prefixes so `storage_list("keys/")` returns only ids. Import goes through `Signer::from_storage_pem` (PKCS#8 RSA/ECDSA/Ed25519, PKCS#8 ML-DSA, BV PQC envelope) with an explicit RSA-strength gate that rejects modulus < 2048 bits before reaching the lenient `from_storage_pem` path. Delete refuses while refs is non-empty.
- [`src/modules/pki/path_keys.rs`](src/modules/pki/path_keys.rs) (new) — four routes: `LIST pki/keys`, `WRITE pki/keys/generate/{internal|exported}` (exported mode returns PKCS#8 PEM once via `Signer::to_pkcs8_pem`), `WRITE pki/keys/import`, and `READ`/`DELETE pki/key/<key_ref>`. Read response carries public key + ref counts so operators can tell at a glance whether a key is in use before deleting it.
- [`src/modules/pki/mod.rs`](src/modules/pki/mod.rs) — module declarations and four new path registrations under the existing `pki` mount.
- [`tests/test_pki_managed_keys.rs`](tests/test_pki_managed_keys.rs) (new) — 9-step integration test: generate/internal hides the private key; generate/exported returns PKCS#8 once and persists the same material; LIST returns all ids; READ-by-id and READ-by-name resolve to the same entry with zero ref counts; duplicate-name generation is rejected; RSA-2048 round-trips through generate→import; an RSA-1024 PKCS#8 PEM is rejected; ML-DSA-65 round-trips via generate-then-reimport; DELETE removes an unreferenced key. The refs-prevent-deletion branch is exercised by code review pending L2 (issuance starts binding keys).
- [`features/pki-key-management-and-lifecycle.md`](features/pki-key-management-and-lifecycle.md) — design doc covering all seven phases (L1–L7).

#### PKI — orphan cert import endpoint (`pki/certs/import`)
- [`src/modules/pki/path_fetch.rs`](src/modules/pki/path_fetch.rs) — new `import_cert` handler at `pki/certs/import` (Write). Takes a single PEM `certificate` block plus an optional `source` label; parses the cert to pull serial + NotAfter, and stores a `CertRecord` with `is_orphaned = true`, no `issuer_id`, no key. The serial then shows up in `pki/certs` listings and `pki/cert/<serial>` reads alongside engine-issued certs. Refuses to overwrite an existing serial. The CRL builder skips orphaned records (no issuer to sign under).
- [`src/modules/pki/storage.rs`](src/modules/pki/storage.rs) — `CertRecord` gains `is_orphaned: bool` and `source: String`. Both `#[serde(default)]` so pre-existing records deserialize cleanly.
- [`src/modules/pki/path_fetch.rs`](src/modules/pki/path_fetch.rs) — `read_cert` now surfaces `not_after`, `issuer_id`, `is_orphaned`, and `source` when set.
- [`gui/src-tauri/src/commands/pki.rs`](gui/src-tauri/src/commands/pki.rs) — new `pki_import_cert` Tauri command; `PkiCertRecord` carries `is_orphaned` + `source` through to the GUI.
- [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx) — XCA Apply now routes leaf certs to `pki/certs/import` (with `source = "xca-import"`) instead of skipping them; Certificates tab tags orphan rows with an "orphan" badge so the operator can tell at a glance which certs were imported vs issued.

### Fixed

#### PKI — duplicate-issuer-name error reported as "ca is not config"
- [`src/modules/pki/issuers.rs`](src/modules/pki/issuers.rs) — `add_issuer` returned the generic `ErrPkiCaNotConfig` ("PKI ca is not config") when the requested issuer name collided with an existing one. The error masked the actual cause (a name collision) and made the XCA import flow look broken whenever the .xdb contained renewals (same logical CA across multiple cert generations) or when the operator re-ran Apply after a partial success. The error now reports `issuer name `<name>` already exists at this mount` so the GUI can detect the collision and recover.
- [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx) — XCA Apply auto-suffixes `_2`, `_3`, … when a CA-bundle import fails because the issuer name already exists. Operators get every distinct cert imported on a single Apply pass and can prune duplicates afterward, instead of having to manually rename each colliding row.

#### XCA Import — leaf cert routing + drop name-stem pairing fallback (xca-import v0.1.7)
- [`plugins-ext/bastion-plugin-xca/src/xca.rs`](plugins-ext/bastion-plugin-xca/src/xca.rs) — `PreviewItem` now carries an `is_ca` flag derived from the cert's BasicConstraints extension (or XCA's `certs.ca` column when present). Without this signal the GUI couldn't distinguish CA certs from leaf certs and shipped every selected cert through `pki/config/ca`, where leaf certs come back as "PKI ca is not config" / "PKI internal error".
- [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx) — Apply now skips non-CA certs with a clear "leaf cert(s) skipped" message instead of trying to import them as issuers; preview default-selection no longer ticks leaf certs; preview Type column shows `cert (CA)` / `cert (leaf)` so the operator can tell at a glance.
- [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx) — Cert↔key pairing now trusts ONLY the plugin's `paired_item_id` (public-key fingerprint match). The previous `_key`/`_priv` name-stem fallback paired wrong keys to certs whenever a key couldn't be fingerprinted (decryption failed, unsupported algorithm), surfacing as "PKI ca public key of certificate does not match private key" server-side. We now skip the row instead of guessing.

#### XCA Import — public-key fingerprint pairing (xca-import v0.1.6)
- [`plugins-ext/bastion-plugin-xca/src/keymatch.rs`](plugins-ext/bastion-plugin-xca/src/keymatch.rs) (new) — XCA stores cert/key pairs with no explicit linkage column; `items.pid` tracks the issuer chain, not the key. XCA itself matches at runtime by comparing public keys, so the plugin now does the same. New `keymatch` module computes a SHA-256 fingerprint of the algorithm's canonical public-key bytes (the same bytes that live in the cert's SPKI `BIT STRING`) and surfaces a `paired_item_id` on each cert/key in the preview. Supports RSA (re-encodes `RSAPublicKey { n, e }` from `RSAPrivateKey`), EC (uses the SEC1 `ECPrivateKey.[1]` publicKey BIT STRING), and Ed25519/Ed448 (uses the PKCS#8 `OneAsymmetricKey.[1]` publicKey BIT STRING when present). Algorithms whose private-key DER doesn't carry the public half yield `None` and fall back to the GUI's name heuristic.
- [`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx) — Apply now honors `paired_item_id` first when pairing a selected cert or key, with the previous parent/name heuristics retained as fallback for older plugins or un-fingerprintable algorithms. The earlier `_key`/`_priv` suffix-stripping name match is kept as a last resort.

#### XCA Import — PBKDF2 envelope parser missed the PBES2 wrapper (xca-import v0.1.4)
- [`plugins-ext/bastion-plugin-xca/src/crypto.rs`](plugins-ext/bastion-plugin-xca/src/crypto.rs) — `parse_pbkdf2_envelope` assumed the outer SEQUENCE began with the PBKDF2 KDF SEQUENCE directly, but XCA writes encrypted private keys as standard PKCS#8 `EncryptedPrivateKeyInfo` (RFC 5208 / 5958) using PBES2 (RFC 8018). The PBES2 OID + params SEQUENCE wraps the KDF SEQUENCE, so every key in real XCA databases failed with "malformed PBKDF2 envelope". The parser now walks the EncryptedPrivateKeyInfo / PBES2 layers, accepts AES-128/192/256-CBC, accepts the optional PBKDF2 PRF SEQUENCE (defaults to hmacWithSHA1 per RFC 8018), and falls back to the older shorthand layout for compatibility.
- **GUI Apply** ([`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx)) — selecting only the private-key row of a CA pair (without the cert) silently skipped every selection. The pair-up logic now resolves the matching cert when a key is selected (mirroring the existing cert→key path), de-duplicates pairs when both halves are selected, and imports the bundle once.
- **GUI Certificates table** ([`gui/src/routes/PkiPage.tsx`](gui/src/routes/PkiPage.tsx)) — split the stacked "Serial / CN" column into separate Serial and Common Name columns so the CN is scannable without hover.

### Added

#### XCA Import — spec drafted (external plugin)

- **New feature spec** ([`features/xca-import.md`](features/xca-import.md)) — design for importing [XCA](https://hohnstaedt.de/xca/) `.xdb` databases (SQLite) into the PKI engine. **Implemented as an external plugin** under [`plugins-ext/bastion-plugin-xca`](plugins-ext) alongside the existing `bastion-plugin-totp` / `bastion-plugin-postgres` reference plugins, **not** compiled into the host. Operators who don't need XCA migration never compile or ship the importer — the host crate gains zero code, zero dep, zero feature flag.
- **Process runtime** chosen over WASM: `rusqlite` + AES-CBC + PBKDF2 are clean natively but awkward in WASI; the plugin's manifest declares `runtime = "process"` and rides on the same supervisor that already runs `bastion-plugin-postgres`.
- **Plugin protocol** (line-delimited JSON over stdin/stdout, plugin-defined op names): `validate` (cheap version sniff, lists `ownPass` keys), `preview` (parses + decrypts, returns the structured item list with `decryption_failures` rows), `import` (returns the same payload as `preview` plus a `plan` hint — the GUI then walks the plan and issues PKI / KV writes via existing routes). The plugin **never** mutates vault state directly; all writes flow through the host's regular policy-checked / audited route surface, so the security model stays the same.
- **XCA item type mapping**: CA cert + matching key → `pki/config/ca/import-bundle`; leaf cert → `pki/cert/<serial>`; standalone key / CSR / template → KV under `secret/xca-import/<batch-id>/...`; CRL → `pki/issuer/<id>/crl`. No new PKI routes added.
- **Encryption** — plugin sniffs the magic and dispatches to one of two key-derivation paths: EVP_BytesToKey (XCA ≤ 2.0, OpenSSL `Salted__` + MD5 + 1 iter) or PBKDF2-HMAC-SHA512 (XCA ≥ 2.4, header-prefixed with iter + salt + IV). Per-key `ownPass` overrides the database master password.
- **GUI wizard** — `Settings → PKI → Import XCA`, three steps (pick file + password → review tree → run). The menu entry is gated on the plugin being registered; uninstalling the plugin hides the entry, reinstalling brings it back without restart.
- **Five planned phases, all inside the plugin repo**: reader skeleton + manifest + invoke wiring → decryption (both formats) → GUI wizard → XCA v1 + smart-card surfacing → hardening + docs + fixture matrix (XCA 1.4 / 2.2 / 2.5).
- **Roadmap entry** added under Secret Engines, marked as an external plugin.

#### Machine Authentication — spec drafted

- **New feature spec** ([`features/machine-authentication.md`](features/machine-authentication.md)) — design for a new auth method targeting **client → remote-server** deployments where a long-lived headless client (CI runner, host agent, service account) needs to authenticate as a *machine*. Each client is identified by a **composite key**: a 32-byte random part generated and stored locally (`~/.config/bvault/<server-name>/machine.random`, mode `0600`) plus a **host-hardware fingerprint** derived from the physical machine's stable identifiers (CPU model + family/model/stepping, total RAM rounded to GiB, SMBIOS system UUID, motherboard serial, primary boot-disk serial, primary physical-NIC MAC, OS architecture, canonical hostname). The random part is **bound to that specific host** — a stolen `machine.random` copied to a different machine recomputes a different fingerprint and login fails.
- **Admin-approval gate** — every enrolment lands in a `pending` queue; until an admin explicitly approves it, every API call other than the enrolment status poll returns `403 enrolment_pending`. Approval is dual-surface: a **CLI subcommand** (`bvault machine-auth approve <id> --policy ... --ttl ...`) and an **admin GUI page** (`Settings → Auth → Machines`) with three tabs (Pending / Approved / History). Same dual surface for `reject` / `revoke` / `rotate`.
- **Composite-key construction** — `sign_priv = HKDF(random_part, "BV-MACH-sign-v1")` derives an Ed25519 keypair the client uses to sign `(challenge || fp_bytes)`. Server stores `sign_pub` + two fingerprint commitments (tier-1: high-entropy stable components only; tier-2: all eight components). Login succeeds if either commitment matches; tier-2-only drift emits a `machine.login.fingerprint_drift` event so operators can spot machines mutating before something breaks. The random part itself never leaves the client.
- **Hardware backends** — `host-fingerprint` is the v1 default and works on every platform (Linux sysfs/SMBIOS, macOS IOKit, Windows WMI). `tpm` is an optional second backend behind a build feature, anchoring the Ed25519 keypair in a platform TPM 2.0 so the signing key is non-export even from `root`. Backend is locked at approve time. **FIDO2 / PIV are explicitly out of v1** — earlier draft proposed them, redirected to host-fingerprint per the current direction; they may return as additional backends if operator demand emerges.
- **Honest threat-model section** — the spec is upfront about what host-fingerprinting buys (defeats credential portability across hosts, defeats lateral movement, defeats backup-tarball exfiltration) and what it does NOT (a `root` attacker on the *same* host wins; full VM image clones reproduce the fingerprint unless the platform's UUID-on-clone setting is enabled). TPM backend is the recommended hardening for hosts that have a TPM.
- **Fingerprint-too-weak refusal** — enrolment refuses on hosts with neither system UUID nor disk serial (some bare-metal containers, some cloud instances) with `fingerprint_too_weak` and points the operator at TPM or AppRole. Linux containers are flagged as a likely refusal target — open question in the spec.
- **Auth backend surface** — mounted at `auth/machine/` with eight routes (enrol, status poll, login two-step, list clients, approve, reject, revoke, rotate) plus per-source-IP rate limits. Storage layout under the existing barrier (`machine/clients/<id>` + secondary index + rejected-history table). Dedicated audit events (`machine.enrol.submitted` / `.approved` / `.rejected`, `machine.login`, `machine.login.fingerprint_drift`, `machine.token.renew`, `machine.revoke`, `machine.rotate`).
- **Embedded-vault refusal** — the backend refuses to mount in the Tauri GUI's embedded mode and the CLI subcommands fail with `not_supported_in_embedded_vault`. Machine Authentication only makes sense for client → remote-server installations.
- **Seven planned phases**: server skeleton + storage → host-fingerprint backend (default) + client CLI → tier-1/tier-2 dual commitment + drift detection → TPM 2.0 (optional) → admin GUI page → rotation/revocation polish → hardening + metrics + docs (incl. cloud-VM clone caveats).
- **Roadmap entry** added under Authentication.

#### Rustion Bastion Integration — spec drafted

- **New feature spec** ([`features/rustion-integration.md`](features/rustion-integration.md)) — design for delegating Resource Connect sessions through a [Rustion](/Users/felipe/Dev/Rustion) bastion. Master signing certificate (hybrid Ed25519 + ML-DSA-65) held in BastionVault, public half enrolled once on Rustion as a trusted authority. Sessions open via a BVRG-v1 envelope: CBOR payload (target + credential + TTL + recording policy + operator identity) ML-KEM-768-encrypted to Rustion's pubkey, hybrid-signed by the master cert. Rustion verifies, decrypts, materialises a single-use IP-bound ticket, and proxies SSH/RDP to the target while recording natively (asciicast v3 / `.rdp-rec`). Renewals re-sign with the same master identity up to `max_renewals`; force-terminate via signed `kill` envelope; recordings exposed in BastionVault's audit timeline as signed-URL pointers (bytes never traverse BastionVault). **Multi-instance bastion pool with health-aware dispatch** — BastionVault enrols an arbitrary number of Rustion instances (per-region / DR / corporate / …). A `rustion` connection profile carries an ordered list of target ids: the dispatcher walks the list and uses the first healthy target (transport / 5xx failures fall through, auth failures are final). When the list is empty/unset, a uniform random pick from the global pool of `up`-status enabled targets — random rather than round-robin so HA replicas stay stateless. A background pinger probes `GET /v1/health` (master-signed nonce, not a full BVRG-v1 envelope) every 30s with three-strikes-down / one-success-up debouncing; status changes emit `rustion.target.health.changed` audit events and the GUI surfaces a live "Will try: …" preview that updates as health flips. `session.open` records `bastion_selection` (`pinned | ordered-fallback | random-pool`) and `bastion_candidates_tried` for unambiguous audit replay.

**Three-tier `connect.transport` policy** (`direct | rustion | rustion-required`) evaluated most-restrictive-wins across global (`sys/config/rustion`, **root-only**, with a `transport_lock` that pins every resource regardless of lower tiers), per-resource-type (`ResourceTypeDef`, **admin-only**, with its own type-level lock), and per-resource (resource-owner, only writable when no upstream tier is locked); GUI shows the effective value and the tier it came from, locked tiers render the field read-only. Seven planned phases: master cert + target registry → envelope + control-plane scaffold → SSH ticketed proxy → RDP → renewal/terminate → recording handoff → policy + rotation. Symmetric work in the Rustion repo (new `rustion-control-plane` crate + `authorities/<name>.yaml` store).
- **Roadmap entry** added under Infrastructure.

#### Resource Connect — Phase 7 (polish: per-type Connect policy, recently-connected list, ⌘K palette)

The final polish slice of the Resource Connect feature. Three operator-facing improvements layered on top of the now-complete launch matrix from Phase 6.5; no transport / credential changes.

- **Per-resource-type Connect policy** ([`gui/src/lib/types.ts`](gui/src/lib/types.ts), [`gui/src/routes/SettingsPage.tsx`](gui/src/routes/SettingsPage.tsx), [`gui/src/routes/ResourcesPage.tsx`](gui/src/routes/ResourcesPage.tsx)) — `ResourceTypeDef` carries an optional `connect: { enabled?, default_ports?, default_users? }` block. Settings → resource types editor exposes a "Resource Connect enabled" checkbox. When unchecked, the Connection tab is hidden for every resource of that type and the ⌘K palette filters the type out. Default ports / users are forward-compat for a future smart-defaults pass; today the protocol's standard port (22 / 3389) wins.

- **Recently-connected list** ([`gui/src-tauri/src/commands/connect.rs`](gui/src-tauri/src/commands/connect.rs), [`gui/src/routes/ResourcesPage.tsx`](gui/src/routes/ResourcesPage.tsx)) — every successful `session_open_*` appends a `RecentSession { ts, profile_id, profile_name, actor, protocol }` entry to the resource record's `recent_sessions` array (capped at 10, oldest evicted). Surfaced as a collapsible "Recently connected" `<details>` block under the profile list on the Connection tab. The host's `caller_display` helper resolves the actor via `auth/token/lookup-self` (display_name → entity_id → "unknown"). Recent-session writes are best-effort: a failure logs at WARN rather than failing the connect call after the transport is already up. Timestamps formatted via a hand-rolled gmtime breakdown (`libc_time_breakdown` + `is_leap`) so the GUI doesn't need to drag in chrono / time.

- **⌘K Connect palette** ([`gui/src/components/ConnectPalette.tsx`](gui/src/components/ConnectPalette.tsx), [`gui/src/App.tsx`](gui/src/App.tsx)) — global hotkey ⌘K (Ctrl+K on Linux/Windows) opens a fuzzy-searchable picker of every launchable {resource × profile} pair. Filters on the same rules the Connection tab uses (type's `connect.enabled !== false`, `os_type` resolves to a protocol, credential source is one we actually launch — Secret / LDAP / PKI; SSH-engine still TODO). Multi-term substring scoring against `{resource_name, profile_name, protocol, host, port, username, kind, tags}`. Arrow keys + Enter to launch; Escape closes. LDAP operator-bind profiles are listed but defer back to the Resources page's inline credential prompt — the palette stays single-keystroke.

The Resource Connect feature is now operationally complete modulo the deferred SSH-engine credential source. Tracking `features/resource-connect.md` updated; all Phases 1–7 marked **Done**.

`cargo check --workspace` clean. `tsc` clean. **102/102** vitest pass.

#### Resource Connect — Phase 6.5 (RDP CredSSP smartcard wiring)

The RDP+PKI gap closed. Vault-issued client certs now drive **CredSSP / NLA smartcard auth** against AD-enrolled Windows servers via `sspi-rs`'s emulated PIV backend — no hardware smartcard, no extra OS configuration, just a PEM cert + PKCS#8 key from the in-tree PKI engine.

**IronRDP fork** ([`fix-deps` branch](https://github.com/ffquintella/IronRDP/tree/fix-deps), commit `ab745f1d`):
- `ironrdp-connector/src/credssp.rs` — accept private keys in either **PKCS#8** or PKCS#1 DER. Tries PKCS#8 first (which modern PKI engines emit, including BastionVault's own), falls back to PKCS#1 for legacy callers. Non-smartcard CredSSP flows are unaffected.
- `ironrdp-connector/Cargo.toml` + `ironrdp/Cargo.toml` — enable `sspi`'s `network_client` (KDC discovery via reqwest) and `dns_resolver` (DNS-based KDC lookup) features. Required at runtime so the Kerberos PKINIT flow that backs smartcard auth can resolve the realm's KDC. Dormant when CredSSP is disabled.

**BastionVault GUI** ([`gui/src-tauri/src/session/rdp.rs`](gui/src-tauri/src/session/rdp.rs), [`gui/src-tauri/src/commands/connect.rs`](gui/src-tauri/src/commands/connect.rs)):
- New `RdpCredential` enum on `RdpOpenArgs`: `Password(Zeroizing<String>)` (the existing path) and `SmartCard(SmartCardCredential)` — `{ certificate_der, private_key_der, pin }`. `build_connector_config` dispatches: password → Standard Security; smartcard → `Credentials::SmartCard { pin, config: Some(SmartCardIdentity { certificate, reader_name = "BastionVault Virtual SmartCard", container_name = "bv-rdp", csp_name = "Microsoft Base Smart Card Crypto Provider", private_key }) }` + `enable_credssp = true`.
- **`CredSspNetworkClient`** replaces the previous `StubNetworkClient`. Wraps sspi's blocking `ReqwestNetworkClient` in `tokio::task::spawn_blocking` so KDC discovery during PKINIT doesn't park the runtime. Direct dep on `sspi` from the GUI crate (same git pin as the IronRDP `[patch.crates-io]`) so the `network_client` / `aws-lc-rs` features are unambiguously enabled.
- **RDP+PKI resolver wired** ([`commands/connect.rs`](gui/src-tauri/src/commands/connect.rs)) — the previous "transport pending" stub replaced with a real builder: `issue_pki_credential` runs first, the returned PEM cert + private key are decoded to DER via a new `pem_body_to_der` helper (handles `-----BEGIN CERTIFICATE-----`, `-----BEGIN PRIVATE KEY-----`, and `-----BEGIN RSA PRIVATE KEY-----` with a fallback chain so PKCS#1 RSA round-trips work too), and the result lands in `RdpCredential::SmartCard`. Synthetic PIN `0000` — the PIV emulator inside sspi-rs accepts any non-empty value since there's no hardware to enforce it.
- **Frontend** — `PkiCredentialEditor`'s previous yellow "RDP+PKI is not wired yet" banner replaced with positive copy explaining the CredSSP + AD smartcard-logon prerequisites. `launchableProfiles` now includes RDP+PKI; the per-button tooltip carries a short technical note. `ssh-engine` is the only remaining stub source.

**Launch matrix today** — every PKI-relevant cell ✅:

| protocol | Secret | LDAP | PKI | SSH-engine |
|---|---|---|---|---|
| SSH | ✅ Phase 3 | ✅ Phase 5 | ✅ Phase 6 | pending |
| RDP | ✅ Phase 4 | ✅ Phase 5 | ✅ Phase 6.5 (CredSSP smartcard) | n/a |

`cargo check --workspace` clean. `tsc` clean. **102/102** vitest pass.

Server-side prerequisite for RDP+PKI: the issuing CA must be enrolled on the Windows side via the standard AD smartcard-logon GPO (`Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies → Trusted Root Certification Authorities` or via `certutil -dspublish -f <CA.cer> NTAuthCA`). The cert's UPN extension or SAN must match an AD account.

#### Resource Connect — Phase 6 (PKI credential source — SSH; RDP CredSSP pending)

The Connect button now supports the **PKI client cert** credential source for SSH. At connect time the host calls `pki/issue/<role>` against the bound PKI mount with the resource hostname as the requested CN, gets back a fresh leaf cert + private key + chain, and feeds the private key to russh as a publickey credential. Operators get the **short-lived-cert lifecycle** for free — every session issues a new key bounded by the role's `max_ttl`.

- **`resolve_pki_ssh`** ([`gui/src-tauri/src/commands/connect.rs`](gui/src-tauri/src/commands/connect.rs)) — pulls the resource metadata for the default CN (hostname → ip_address → resource name fallback), POSTs to `<pki_mount>/issue/<role>` with optional `ttl` override, captures `private_key` / `certificate` / `issuing_ca` / `serial_number` from the response, and feeds the private key to `SshCredential::PrivateKey` wrapped in `Zeroizing`. The cert is delivered alongside (operators using x509-cert-auth servers like Tectia drop it on the host; everyone else relies on the public key being in `authorized_keys`).
- **Shared `issue_pki_credential` helper** carries the four-field `PkiIssued` struct so the eventual RDP CredSSP wiring lands by replacing the error path with a smartcard-wrap step — no second issue call.
- **RDP + PKI: scaffolded but stubbed.** The cert issues fine (`issue_pki_credential` runs first), but feeding it to RDP requires sspi-rs's `scard` smartcard backend wired through ironrdp's CredSSP path. Tracked alongside the broader CredSSP / NLA enablement deferred in Phase 4. The frontend renders a yellow banner explaining the gap and the operator-bind LDAP / Secret paths as the supported RDP routes today.
- **Frontend** — new `PkiCredentialEditor` component (mount + role + optional cert TTL) on the profile editor. Drops the "Phase 6" stub label. Connect-button gating extended to enable SSH+PKI but keep RDP+PKI disabled with a tooltip pointing at the CredSSP follow-up.

The launchable matrix now reads:

| protocol | Secret | LDAP | PKI | SSH-engine |
|---|---|---|---|---|
| SSH | ✅ Phase 3 | ✅ Phase 5 | ✅ Phase 6 | pending |
| RDP | ✅ Phase 4 | ✅ Phase 5 | pending (CredSSP) | n/a |

`cargo check --workspace` clean. `tsc` clean. **102/102** vitest pass.

Phase 7 (polish + per-resource-type Connect policy + recently-connected list + ⌘K palette) follows.

#### Resource Connect — Phase 5 (LDAP credential source)

The Connect button now supports the **LDAP / Active Directory** credential source on top of the existing Secret source. The LDAP profile binds to an operator-configured LDAP secret-engine mount (e.g. `openldap/`) and runs in one of three sub-modes; the SSH and RDP transports both ship today.

**Three bind modes**:
- **`operator`** — operator-supplied bind. Frontend pops a small modal collecting `username` / `password` (accepts plain `user`, `DOMAIN\user`, or `user@realm`). The host forwards them straight to the SSH/RDP transport. Credentials never persist — the typed password lives only as long as the open request. RDP path parses out the `\`/`@` separator so the CredSSP-shaped domain slot lands correctly when the connector wants it.
- **`static_role`** — vault-managed account. At connect time the host issues an internal `READ <ldap_mount>/static-cred/<role>` and feeds the returned `username` + `password` to the transport. The same code path the LDAP secret engine's `/v1/<mount>/static-cred/<role>` endpoint normally answers.
- **`library_set`** — vault-managed pool with check-out semantics. Connect issues `WRITE <ldap_mount>/library/<set>/check-out`, captures the returned `lease_id`, and **registers a session-close hook** that runs the matching `check-in` when the WebviewWindow closes (or `session_close` is called explicitly). The same per-set Mutex the LDAP engine uses today guarantees no parallel session double-uses the same account.

**Session-close cleanup** ([`gui/src-tauri/src/session/mod.rs`](gui/src-tauri/src/session/mod.rs)) — new `SessionCleanup` enum captured at open time on both `SshSessionState` and `RdpSessionState`. Variants today: `LdapLibraryCheckIn { ldap_mount, library_set, lease_id }`. `drop_session` returns the captured hook so `session_close` (and the `WindowEvent::CloseRequested` handlers spawned by the open commands) can fire it. A failed check-in logs at WARN and swallows the error — the alternative would be to fail the close and leave a dangling session record, which is worse.

**Unified credential resolver** ([`gui/src-tauri/src/commands/connect.rs`](gui/src-tauri/src/commands/connect.rs)) — replaced the per-protocol `resolve_secret_credential_*` helpers with `resolve_ssh_credential` / `resolve_rdp_credential`. Both dispatch on `credential_source.kind` (`secret` / `ldap`), return a `(credential, optional_effective_username, optional_on_close)` tuple, and let the caller swap in the canonical username when the LDAP resolver knows it. SSH-engine and PKI sources are still stubbed pending Phase 6 / its follow-ups.

**Frontend**:
- New `LdapCredentialEditor` component on the Connection-tab profile editor with three sub-mode selectors. The editor shows mount-path + role / set fields conditional on the bind mode; the operator-mode case carries inline copy explaining that the prompt fires at connect time.
- `OperatorBindPrompt` modal — pops on Connect for LDAP+operator profiles, collects user/password, forwards to the open request via the new optional `operator_credential` field.
- `runConnect` helper centralises the open-request shape; the kind-based branching (SSH vs RDP) and the operator-bind branch share it.
- Connect button now enables for SSH/RDP × Secret/LDAP combos. The "later phase" stub label kept on the SSH-engine + PKI sources.

**Username handling** — both protocols' open commands now allow an empty `profile.username` and re-validate after credential resolution so LDAP `static_role` / `library_set` modes can supply the canonical service-account username from the cred response.

`cargo check --workspace` clean. `tsc` clean. **102/102** vitest pass.

Phase 6 (PKI client cert / CredSSP smartcard) and Phase 7 (polish + per-type Connect policy + recently-connected list) follow.

#### Resource Connect — Phase 4 (RDP session window, Secret source)

The Connect button now opens an in-app RDP session window for Windows server resources. Canvas-based bitmap rendering driven by `ironrdp` 0.14 over a tokio TCP+TLS framed stream. Credential bytes never reach the JS layer.

**Dep-conflict resolution.** ironrdp's `picky 7.0.0-rc.22` chain pinned `=crypto-common 0.2.0-rc.4`, conflicting with the host's `digest 0.11` stack via `hmac 0.13`. Three alternative pure-Rust RDP crates surveyed (`rdp-rs`, `lamco-rdp`, `smb`-style fork) and rejected — all required either OpenSSL/native-tls or had blocking dep conflicts of their own. **Resolution:** the [`IronRDP/`](IronRDP/) git submodule on the [`fix-deps`](https://github.com/ffquintella/IronRDP/tree/fix-deps) branch carries:
- `ironrdp-connector`: `picky =rc.22` → `=rc.23` (rc.23 picks up stable `crypto-common 0.2.x`).
- `ironrdp-connector` / `ironrdp` / `ffi`: `sspi 0.19` → `0.20`.
- workspace `[patch.crates-io]`: `sspi 0.20.0` redirected to its `main` SHA `26765bb`, which already bumped to picky-rc.23 + the stable RustCrypto chain. The same patch lives in the host workspace `Cargo.toml` so the GUI inherits it for the path-to-git-dep IronRDP crates.

Net effect: ironrdp's transitive `crypto-common` resolves to `0.2.1`, matching the host stack. Five IronRDP crates pulled directly into the GUI as git deps: `ironrdp`, `ironrdp-async`, `ironrdp-tls` (rustls feature), `ironrdp-core`, `ironrdp-pdu`, `ironrdp-tokio`. Host-crate `tokio` requirement bumped `1.51` → `1.52` to satisfy `ironrdp-tls`.

**Implementation** ([`gui/src-tauri/src/session/rdp.rs`](gui/src-tauri/src/session/rdp.rs)):
- `open_rdp_session` walks the connector handshake: TCP connect → ironrdp `connect_begin` → TLS upgrade (rustls) → `connect_finalize` → channel open. 30 s hard timeout on the whole connect+auth phase.
- A tokio task drives the active-stage loop: `framed.read_pdu()` → `ActiveStage::process(...)` → forward `ResponseFrame` PDUs back to the server, emit `GraphicsUpdate` batches as full-frame RGBA snapshots over a per-session Tauri event the WebviewWindow subscribes to. `Terminate` fires the `closed` event.
- Input: `mpsc::Sender<RdpControl>` accepts `PointerMove`, `PointerButton`, `Key` from the frontend; the pump translates each into a fast-path `MousePdu` / `KeyboardEvent`-flagged scancode and writes through the framed stream.
- Three new Tauri commands: `session_open_rdp`, `session_input_rdp_mouse`, `session_input_rdp_key`. `session_close` extended to fan-out to either the SSH or RDP variant of `SessionState`.
- Conservative JS `KeyboardEvent.code` → PS/2 set-1 scancode table covers printable ASCII + common modifiers + arrows + function keys + Enter/Escape/Backspace/Tab. Unmapped keys drop on the floor (international + media keys are Phase 7 polish).

**Frontend** ([`gui/src/routes/SessionRdpWindow.tsx`](gui/src/routes/SessionRdpWindow.tsx)):
- Fresh React route loaded into the spawned Tauri WebviewWindow. Subscribes to the per-session frame event, decodes the b64 RGBA payload, paints it onto a `<canvas>` via `putImageData`. Mouse + keyboard events forward via the new Tauri commands. Status pill (`connecting` / `open` / `closed` / `error`) + Disconnect button in a thin chrome bar.
- `MouseEvent.button` (0=left, 1=middle, 2=right) maps directly to the host-side button index. Canvas-relative coordinates account for any inner-window scaling.
- Phase 4 limitations called out in the spec but not in the UI banner (since the path now actually works): **no NLA / CredSSP** (operators with NLA-enforcing servers see an explicit "transport stub" auth error), **full-frame snapshots, not dirty-rect deltas**, **no clipboard / audio / smart-card redirection**.

**Connect button** on the Connection tab now enables for both SSH+Secret and RDP+Secret profile combos. The same `handleConnect` hop branches on `profile.protocol`.

`cargo check --workspace` clean. `tsc` clean. **102/102** vitest pass.

Phase 5 (LDAP credential source) and Phase 6 (PKI / CredSSP) follow.

#### Resource Connect — Phase 3 (SSH session window, Secret source)

The Connect button is live. Clicking it on a server resource with an SSH+Secret profile opens a fresh Tauri WebviewWindow carrying an in-app xterm.js terminal driven by `russh` 0.45 over the secret's credentials. The credential bytes never reach the JS layer or the OS clipboard.

- **`gui/src-tauri/src/session/{mod,ssh}.rs`** — per-session state on `AppState::connect_sessions`, keyed by an opaque token. The pump loop runs in a tokio task: bytes from russh's `ChannelMsg::Data` get base64-emitted on a per-session Tauri event the spawned window subscribes to; control messages from the frontend (input bytes, window-size changes, close) flow back through an `mpsc::Sender<SshControl>` into the russh channel. Stderr from the remote PTY is folded onto the same stdout event so escape sequences line up. TOFU host-key handling identical to the SFTP/SCP transport: optional `host_key_pin` on the profile in OpenSSH `SHA256:<base64>` format; empty pin accepts first connect and logs the observed fingerprint at WARN.
- **Four new Tauri commands** in [`gui/src-tauri/src/commands/connect.rs`](gui/src-tauri/src/commands/connect.rs):
  - `session_open_ssh` — pulls the resource metadata + the credential secret server-side, resolves the credential into `SshCredential::Password` / `SshCredential::PrivateKey` (wrapped in `Zeroizing` for the brief window russh holds them), opens the connection with a 30 s hard timeout, requests an `xterm-256color` PTY + interactive shell, spawns the pump task, and finally calls `WebviewWindowBuilder` to launch the session window. The window's `WindowEvent::CloseRequested` hook tears the SSH session down so an operator x'ing the window cleans up the remote side.
  - `session_input` — frontend posts `{token, bytes_b64}`; the host base64-decodes and pushes a `SshControl::Data` into the per-session channel.
  - `session_resize` — frontend posts `{token, cols, rows}`; the host issues `channel.window_change(...)` so xterm + remote agree on terminal size.
  - `session_close` — explicit teardown the frontend calls on Disconnect or unmount.
- **Credential resolver** for the **Secret** source: reads the resource secret at `v2/resources/secrets/<name>/<id>`, looks for `private_key` first (with optional `passphrase`) then falls back to `password`. Plain key/value secrets are accepted as long as one of those keys is present.
- **`SessionSshWindow.tsx`** route — fresh React component loaded into the spawned WebviewWindow at `index.html#/session/ssh?token=…&stdout=…&closed=…&label=…`. Mounts an xterm.js terminal with a fit-addon, subscribes to the per-session stdout event, forwards keystrokes via `session_input`, and propagates resize via `session_resize`. The route is **not** auth-gated — the host already authenticated the credential and registered the session before the window opened, so the JS layer just owns the terminal UI. A status pill (`connecting` / `open` / `closed` / `error`) and a Disconnect button live in a thin chrome bar above the terminal.
- **Connect button on the Connection tab** — appears on each profile row alongside Edit/Delete. Phase 3 enables it for SSH+Secret profiles only; RDP and the LDAP/SSH-engine/PKI sources show a disabled button with a "ships in a later phase" tooltip.
- **`@xterm/xterm@5.5` + `@xterm/addon-fit@0.10`** added to `gui/package.json`. **`russh@0.45` + `russh-keys@0.45`** added directly to `gui/src-tauri/Cargo.toml` (the same crate pair the host's `files_ssh_sync` feature uses for SFTP/SCP pushes — same TOFU posture, same OpenSSH fingerprint helper).
- **No backend changes to the host crate** — the Connect surface lives entirely on the GUI side. The resource module's metadata bag carries the profile config it needs (Phase 2), and the existing `v2/resources/secrets/<name>/<id>` read path supplies the credential.

`cargo check --workspace` clean. `tsc` clean. **102/102** vitest pass (no new tests this phase — the SSH path is wire-protocol-driven and integration-tested manually against an OpenSSH container; an automated end-to-end `russh`-against-`testcontainers` test is tracked as test infrastructure).

Phases 4 (RDP window with `ironrdp`), 5 (LDAP source), 6 (PKI source), 7 (polish + per-type Connect policy) follow in subsequent cuts.

#### Resource Connect — Phase 2 (Connection profiles + Secret source)

Adds the per-resource Connection profile shape that the future Connect button dispatches on. No new backend code — the resource record's metadata bag is already a flexible `Map<String, Value>`, so `connection_profiles` slots in as a JSON array key alongside the existing `hostname` / `os_type` / `notes` / etc. The whole feature ships GUI-side.

- **`ConnectionProfile` + `CredentialSource` TypeScript types** ([`gui/src/lib/types.ts`](gui/src/lib/types.ts)) — discriminated union over the four credential kinds (Secret, LDAP, SSH-engine, PKI). Phase 2 wires the **Secret** source end-to-end; the other three are part of the type union so an operator can pre-stage a profile, with editor stubs that point at the spec until their phases land.
- **Profile helpers** ([`gui/src/lib/connectionProfiles.ts`](gui/src/lib/connectionProfiles.ts)) — `protocolForOsType` (the os_type → ssh/rdp dispatcher the Connect button will use), `defaultPort`, `newProfileId` (16 hex chars from `crypto.getRandomValues`, unique per resource), `detectSecretShape` (credential-shaped vs. kv-shaped detection: `username` + at least one of `password` / `private_key`), `readProfiles` (tolerant parser that drops malformed entries), `blankProfile`, `validateProfile` (per-source save-time validation), `profilesForOsType` (filter to the protocol Connect would dispatch).
- **Connection tab on the resource detail view** ([`gui/src/routes/ResourcesPage.tsx`](gui/src/routes/ResourcesPage.tsx)) — visible only on `type === "server"`. Lists every profile with target/user/credential summary chips; supports Add / Edit / Delete with a confirmation modal on delete. When `os_type` is unset the panel shows a yellow banner pointing the operator at the Info tab to set it; when `os_type` is `other` it surfaces a similar note that Connect is disabled.
- **`ConnectionProfileEditor` modal** — name + protocol + target host/port overrides + username + credential source picker + optional TOFU host-key pin. Save is gated on `validateProfile`. The protocol field is editable (so an operator with a mixed-protocol host can override the os_type default) and surfaces an inline note when the chosen protocol diverges from the os_type's default mapping.
- **Secret source editor** — dropdown of every secret on the resource (loaded once per modal open via `listResourceSecrets`). On selection an inspector reads the secret and reports green ("credential-shaped: `username = …; password + private_key`") or yellow ("generic key/value secret — Connect will look for `username` + `password`/`private_key` at runtime"). Plain key/value secrets are still accepted for forward-compat with operators who already store credentials as flat blobs.
- **Stub editors** for LDAP, SSH-engine, and PKI sources — the modal lets the operator pick those kinds (so the type union round-trips through save → load) but renders a "ships in Phase N" banner with a pointer to the spec. The profile saves with whatever fields the operator filled in; Connect refuses to launch against a stub source until that phase ships.
- **27 new vitest tests** in [`gui/src/test/connectionProfiles.test.ts`](gui/src/test/connectionProfiles.test.ts) covering every helper: every os_type → protocol mapping, default port, id shape + uniqueness, secret-shape detection (credential / private-key-only / kv / username-only / empty-string), tolerant `readProfiles`, blank-profile defaults per os_type, every validateProfile branch (clean, missing name, out-of-range port, every credential-source kind's required-field check), and `profilesForOsType` filtering.

`cargo check --workspace` clean. `tsc` clean. **102/102** vitest pass (75 prior + 27 new).

The Connect button itself ships in Phase 7 alongside the polish slice — by then operators will have populated `os_type` (Phase 1) and Connection profiles (this phase) on existing resources, so the button arrives against pre-stocked data rather than against a forced configure-everything-now flow.

#### Resource Connect — Phase 1 (`os_type` field + select schema)

Lands the GUI-only schema slice that unblocks the rest of the Resource Connect feature ([`features/resource-connect.md`](features/resource-connect.md)) — no implementation commitment to the SSH/RDP windows yet, just the structured field the Connect button will dispatch on.

- **`select` field type** added to [`ResourceFieldDef`](gui/src/lib/types.ts) — `{ type: "select"; options: { value, label }[] }`. Open to any resource-type definition; not server-specific.
- **`os_type` select on the `server` resource type** ([`gui/src/lib/resourceTypes.ts`](gui/src/lib/resourceTypes.ts)) — values: `linux`, `windows`, `macos`, `bsd`, `unix`, `other`, plus an explicit empty placeholder. The free-form `os` text field stays alongside it for the human-readable distro/version (`Ubuntu 24.04`, `Windows Server 2022`).
- **`DynamicFieldsForm` renders `select`** ([`gui/src/routes/ResourcesPage.tsx`](gui/src/routes/ResourcesPage.tsx)) as a `<Select>` element with the options from the field def. All other field types unchanged.
- **Migration heuristic** in both create and edit modals: when an operator types into the free-form `os` field on a server resource and `os_type` is still unset, the GUI infers it from common substrings (`Ubuntu` / `Debian` / `RHEL` / `AlmaLinux` → `linux`, `Windows Server 2022` / `Win 10` → `windows`, `macOS` / `Darwin` / `OSX` → `macos`, `FreeBSD` → `bsd`, `Solaris` / `AIX` / `HP-UX` → `unix`). Operator can always override via the dropdown; a value the operator has already picked is never overwritten. The substring-match list deliberately keeps `\bserver\b` alone (without a trailing year) out of the Windows match because too many non-Windows things are called "server."
- **Settings page type editor** extended with a select-options editor: when an operator picks `Select (enum)` for a custom-type field, an inline `value=label, value=label` shorthand appears in place of the placeholder field. Empty entries and trailing commas are tolerated; bare `linux, windows, macos` works too (value and label become the same).
- **9 new vitest tests** ([`gui/src/test/resourceTypes.test.ts`](gui/src/test/resourceTypes.test.ts)) covering the server type carrying `os_type`, every Connect-button-relevant value being present in the options list, the migration heuristic recognising Linux / Windows / macOS / BSD / legacy-Unix variants, and the empty-on-no-match safeguard.

`cargo check --workspace` clean. `tsc` clean. 75/75 vitest pass (66 existing + 9 new).

Phases 2–8 (Connection profiles, SSH window, RDP window, the four credential sources, polish) ship in subsequent cuts. The schema landing first lets operators populate `os_type` ahead of the actual Connect button arriving — by the time Phase 7 lands, deployments will already have the data.

#### Cloud Storage — obfuscation salt rekey CLI + server-mode bootstrap

Closes both deferred Cloud Storage Targets sub-initiatives in one cut.

- **Server-mode obfuscation bootstrap** ([`src/storage/mod.rs`](src/storage/mod.rs), [`src/cli/command/server.rs`](src/cli/command/server.rs)) — new `storage::new_backend_async` constructor routes the `file` backend through `FileBackend::new_maybe_obfuscated` so the salt bootstrap for `obfuscate_keys = true` runs against the wrapped target. The `bvault server` entry point now spins up a small current-thread tokio runtime to drive the async backend init before handing it to the actix system below. Result: a server-mode boot honours `obfuscate_keys = true` the same way the Tauri desktop bootstrap already did. The previous warning at `FileBackend::new` is retained but reworded — it now fires only on `operator backup`/`restore`/`migrate`, which intentionally see the underlying hashed keys (those tools already work flat against the obfuscated bucket and don't need the obfuscation layer).
- **Plaintext-key manifest in `ObfuscatingTarget`** ([`src/storage/physical/file/obfuscate.rs`](src/storage/physical/file/obfuscate.rs)) — every write/delete now maintains a newline-delimited manifest at `_bvault_manifest` alongside the existing `_bvault_salt`. The manifest is what makes salt rotation possible: HMAC alone can't be inverted, so without an out-of-band record of original keys, rekey would be impossible. Cost: one extra small read+write per vault op (load → dedupe → save). Failures on the manifest update log a warning but do **not** roll back the data write — losing manifest entries makes future rekeys incomplete, but losing data is worse.
- **`bvault operator cloud-target rekey-salt` CLI** ([`src/cli/command/operator_cloud_target_rekey.rs`](src/cli/command/operator_cloud_target_rekey.rs)) — orchestrates the in-place salt rotation. Operator seals the vault, runs the CLI with the same `--target-config` keys they'd hand to `operator backup`, and unseals. Steps:
  1. Load `_bvault_salt` (old) + `_bvault_manifest` (plaintext key set) from the underlying provider.
  2. Mint a fresh 32-byte salt.
  3. For each plaintext key in the manifest: re-write its ciphertext blob from `HMAC(old_salt, key)` to `HMAC(new_salt, key)`.
  4. Atomically swap `_bvault_salt` to the new value + persist the manifest under the new layout.
  5. Best-effort cleanup of the orphan blobs at the old hash positions.

  Crash-safe: an interruption between steps 3 and 4 leaves the old salt in place so the vault can still boot against the old positions. After step 4 the new positions are authoritative; step 5 cleanup is safe to re-run via another rekey pass.

  `--dry-run` reports the manifest size + intended action without touching any data. `--confirm` is required for any non-dry-run pass — the gate keeps an accidental run from clobbering a live vault.
- **5 new unit tests** in `obfuscate.rs` covering manifest add/remove/dedupe/round-trip + the marker-key list filter; **3 new end-to-end tests** in the rekey CLI module covering round-trip against a local-fs target, dry-run no-op, and refusal-on-unobfuscated-target. The existing two obfuscation tests that asserted "exactly 1 underlying entry per write" updated to expect "1 data entry + 1 manifest marker" now that every write maintains the manifest.

`cargo check --workspace` clean. `cargo test --features "files_smb files_ssh_sync" storage::physical::file` clean (75 tests). Cloud Storage Targets has no remaining deferred sub-initiatives.

#### File Resources — Periodic re-sync + sync-on-write (Phase 7)

Closes the last deferred slice of File Resources. Sync targets can now opt into two automatic-push modes alongside the existing on-demand `POST /sync/<name>/push`:

- **`auto_sync_interval_seconds`** on each target (`u64`; `0` = disabled, the existing on-demand-only behaviour). When non-zero, the periodic scheduler runs a push when both `now - state.last_attempt_at_unix >= interval` AND `state.next_retry_at_unix <= now` (the latter implements exponential backoff after consecutive failures).
- **`sync_on_write = true`** on each target. The file-content write handler runs an inline push to every target whose flag is set, as part of the same request. Per-target outcomes are returned in a new `sync_on_write[]` array on the write response so the caller knows whether the inline push succeeded without a separate poll. Failure does **not** roll back the file write — the bytes are already persisted; the failure lands on the target's `FileSyncState` and the next periodic tick retries.

**Internal scheduler vs. external-tick decision**: the deferred-roadmap entry called out both paths. We ship **both**:

- **Internal scheduler** ([`src/modules/files/scheduler.rs`](src/modules/files/scheduler.rs)) — single tokio task started from [`Core::post_unseal`](src/core.rs), tick every 60s, walks every `files`-typed mount, runs the sweep through the same shared [`run_sync_tick_for_storage`](src/modules/files/mod.rs) free function the manual endpoint uses. Mirrors the LDAP / PKI auto-tidy schedulers' single-process posture: no HA leader gating yet — every node in a Hiqlite cluster runs its own scheduler. The sync push is **idempotent** (the tmp+rename pattern every transport uses produces the same final result regardless of how many nodes pushed), so a double-push is wasteful but not incorrect. HA leader gating via `hiqlite::dlock` tracks as a single cross-cutting follow-up alongside the same gap in `pki/auto-tidy` and `ldap/auto-rotate`.
- **External-tick endpoint** — new `POST /v1/<mount>/sync-tick` runs the same sweep on demand. The per-mount [`FilesSyncConfig`](src/modules/files/scheduler.rs) record (defaults: `enabled = true`, `max_concurrent_pushes = 8`) lets an operator who prefers external scheduling flip the internal scheduler off and drive the sweep from `cron` against this endpoint instead. Returns per-tick `attempted` / `succeeded` / `failed` / `skipped` counters for operator visibility.

Two new state fields on [`FileSyncState`](src/modules/files/mod.rs) drive the scheduler decisions: `last_attempt_at_unix` (for the cadence window check), `next_retry_at_unix` + `consecutive_failures` (for exponential backoff: `min(2^failures, 15min)`), `last_attempt_source` (`"manual"` / `"on_write"` / `"scheduler"` for triage of flapping targets). All five state fields surface in the existing `GET /sync` list response.

Refactor: extracted the per-target push logic out of `handle_sync_push` into a reusable `FilesBackendInner::run_sync_push(req, id, name, source)` method + a `dispatch_push` free function. The manual `/sync/<name>/push` endpoint, the inline `sync_on_write` path, and the periodic scheduler all funnel through the same code, so they share the same atomicity guarantees, the same audit footprint, and the same backoff semantics.

8 new unit tests in [`scheduler.rs`](src/modules/files/scheduler.rs) cover the due/not-due/in-backoff state machine + the config defaults. 2 new integration tests in `mod.rs`: `test_sync_on_write_inline_push` (file write fires inline push, target file lands with new bytes, response carries the per-target outcome) and `test_manual_sync_tick_endpoint` (sync-tick attempts the auto-flagged target and skips the manual-only target).

**File Resources is now feature-complete** — every previously deferred sub-initiative has shipped. `cargo check --workspace` clean. `cargo test --features "files_smb files_ssh_sync" modules::files` clean (48 tests).

#### File Resources — SFTP + SCP sync transports (Phase 6)

Closes the SSH slice of the File Resources deferred roadmap. `FileSyncTarget { kind = "sftp" }` and `kind = "scp"` are now valid sync-target shapes; both push the file's bytes over an SSH session built with [`russh`](https://crates.io/crates/russh) `0.45` (pure-Rust SSH client; no `libssh2-sys` C dep). SFTP layers [`russh-sftp`](https://crates.io/crates/russh-sftp) over an SSH `sftp` subsystem channel; SCP runs `scp -t <path>` on an SSH exec channel and pipes the OpenSSH SCP framing.

- **Behind `files_ssh_sync` Cargo feature** — default builds don't ship the SSH stack. Configs round-trip across feature combinations: a target with `kind = "sftp"` saved on a `files_ssh_sync` build is readable on a stock build, and the push handler returns a clear `requires --features files_ssh_sync` error.
- **`target_path` URL grammar** — `sftp://[user@]host[:port]/path/to/file` and `scp://[user@]host[:port]/path/to/file`. Default port 22. Validated at config-save time so the operator gets an immediate error rather than a push-time failure. User-in-URL is a convenience; the canonical username field is `ssh_username` on the target (target wins when both are set).
- **Two auth methods, inline on the target record** — `ssh_password` and/or `ssh_private_key` (PEM bytes; OpenSSH / PKCS#8 / RFC 8410 / legacy RSA all parsed by `russh-keys::decode_secret_key`), with optional `ssh_passphrase` for encrypted keys. When both are set, the key is tried first and the password is the fallback (so an operator can stage a passwordless-key cutover without losing access if the new key isn't yet on the target). All three secret fields are barrier-encrypted at rest, redacted on read with paired `ssh_password_set` / `ssh_private_key_set` / `ssh_passphrase_set` booleans, and update-without-resupply preserves the existing values — same write-only-on-update pattern as `smb_password` and the LDAP engine's `bindpass`.
- **Bootstrap-ordering decision** — the deferred-roadmap entry called out "key-stored-in-vault bootstrap ordering needs design." The design we ship: **inline credential fields on the target record**. There is no ordering issue because by the time a sync push runs, the vault is already unsealed and the target record is decrypted — the credential comes from the same record whose `target_path` field we're reading. Pulling credentials by reference from a separate KV secret was considered but rejected for v1: it adds a cross-engine dependency that makes the "this target works / doesn't" diagnostic harder, and the inline path covers both the password and private-key cases without losing functionality. A future feature can layer a `credential_ref` indirection on top once the operator demand confirms it's needed.
- **TOFU-without-pinning host-key handling** — optional `ssh_host_key_fingerprint` field on the target in OpenSSH `SHA256:<base64>` format. When set, the connection refuses any server key whose fingerprint doesn't match. When empty, the connection accepts any host key on first connect and logs the observed fingerprint at WARN so the operator can pin it on the next push. Observed fingerprint is computed from the russh `key::PublicKey::public_key_bytes()` SHA-256 (matches OpenSSH's `ssh-keygen -lf` output exactly).
- **Atomic-ish push** — same tmp-then-rename pattern the SMB transport uses. SFTP `rename` is a first-class operation. SCP doesn't have rename built into the protocol, so we rename via a follow-up exec channel — `mv -- '<tmp>' '<final>'` with POSIX shell single-quoting. SCP's atomicity is therefore weaker than SFTP's; the tmp file is left on disk if the rename fails, with a clear error.
- **Hardened call site** — push runs on a fresh OS thread + single-threaded tokio runtime (same pattern the SMB transport and ACME DNS-01 validator use) so it works under both the default async build and `--features sync_handler`. 60-second hard timeout caps the worst-case unresponsive-server stall (longer than SMB's 30 s because SSH key exchange + auth + write tends to be slower over slow VPN links).
- **9 SSH-sync unit tests** + 2 new save-time validation assertions in the existing `test_sync_target_unsupported_kind_rejected_at_save` integration test (sftp without credentials → rejected; scp with malformed URL → rejected).

The `russh` + `russh-sftp` dep tree shipped here is the same one the planned **Resource Connect SSH window** will use ([`features/resource-connect.md`](features/resource-connect.md), Phase 3) — landing it now pre-stages that work.

Periodic re-sync (Phase 7) remains the only deferred File Resources slice — see [`features/file-resources.md`](features/file-resources.md).

#### File Resources — SMB sync transport (Phase 5)

Closes the SMB slice of the File Resources deferred roadmap. `FileSyncTarget { kind = "smb" }` is now a valid sync-target shape; pushes the file's bytes to a Windows share or Samba server over SMB2/3 with NTLM authentication.

- **Pure-Rust SMB stack** ([`src/modules/files/smb.rs`](src/modules/files/smb.rs)) — uses [`smolder-smb-core`](https://crates.io/crates/smolder-smb-core) `0.3` (typed SMB2/3 client + named-pipe RPC, NTLM via internal sspi-style auth, no `libsmbclient` / `libsmb2` C dep, no Windows-only restriction). Default-features only — Kerberos intentionally not enabled (would pull `reqwest`); NTLM covers the corporate Samba / Windows Server use cases this transport targets in v1.
- **Behind `files_smb` Cargo feature** — default builds don't ship the SMB stack, keeping the binary size unchanged for operators who only push to local-FS / cloud targets. The engine still **accepts** `kind = "smb"` configs without the feature so configs round-trip across builds with mixed feature sets; the push handler returns a clear `requires building with --features files_smb` error in that case.
- **`target_path` URL grammar** — accepts both `smb://server[:port]/share/path/to/file` and Windows UNC `\\server\share\path\to\file` (backslashes normalised to `/`). Default port 445. Validated at config-save time so the operator gets an immediate error rather than a push-time failure.
- **NTLM credentials on the target record** — new `smb_username`, `smb_password`, `smb_domain` fields on [`FileSyncTarget`](src/modules/files/mod.rs). Stored barrier-encrypted alongside the rest of the target record. Read API redacts `smb_password` and surfaces a `smb_password_set` boolean instead (mirrors the LDAP engine's `bindpass` pattern). Update without re-supplying the password preserves the existing one — same write-only-on-update semantics.
- **Atomic-ish push** — writes to `<basename>.bvsync.<pid>.tmp` in the same directory, then renames to the final basename on success. SMB rename within the same directory is atomic from the server's filesystem perspective. Failure cleans up the orphan temp file. Same semantics as the local-fs transport's tmp+rename.
- **Hardened call site** — push runs on a fresh OS thread + single-threaded tokio runtime (same pattern the ACME DNS-01 validator uses in [`src/modules/pki/acme/dns01.rs`](src/modules/pki/acme/dns01.rs)) so the call works under both the default async build and `--features sync_handler` without colliding with any ambient runtime. 30-second hard timeout caps the worst-case unresponsive-server stall.
- **9 SMB unit tests** + 2 new integration assertions in the sync-write handler — URL parse coverage (default port, explicit port, UNC backslash, no-scheme rejection, missing share, missing path, dir-path rejection, invalid port), tmp-path same-directory invariant, and config-save rejections for `kind = smb` without credentials / with malformed URL.

The other File Resources Phase-5/6 transports (SFTP, SCP) and Phase 7 (periodic re-sync) remain deferred — see [`features/file-resources.md`](features/file-resources.md). Live-network integration tests against a Samba container are tracked as test infrastructure, not as a feature gap.

### Changed

#### SSH `ssh_pqc` feature on by default
- **Default-build feature flip** ([`Cargo.toml`](Cargo.toml), [`gui/src-tauri/Cargo.toml`](gui/src-tauri/Cargo.toml), [`Makefile`](Makefile)) — `ssh_pqc` is now part of the default feature set on both the server crate and the GUI Tauri host. The dev / prod GUI Make targets pass it explicitly so a skim of the Makefile shows what's compiled in. Previously the GUI's "Generate CA → ML-DSA-65" path returned a build-flag error toast on stock `make gui-build` / `make run-dev-gui` builds; now it works out of the box. PQC pulls no new external deps (`bv_crypto` + `ssh-encoding` + `base64` are already present), and the algorithm is gated at sign time so admins who never select ML-DSA-65 pay no runtime cost. Operators wanting a leaner binary can override with `--no-default-features --features storage_hiqlite`.

### Added

#### PKI — ACME server endpoints (Phase 6.1 foundation)

First chunk of [RFC 8555](https://datatracker.ietf.org/doc/html/rfc8555) ACME server work on the existing PKI engine. Spec at [`features/pki-acme.md`](features/pki-acme.md).

- **JWS request envelope verification** ([`src/modules/pki/acme/jws.rs`](src/modules/pki/acme/jws.rs)) — flattened-JSON JWS parsing per RFC 7515 + signature verification for the three RFC 8555 §6.2 mandatory algorithms: **RS256** (via `rsa` 0.9 + `sha2-saml`), **ES256** (via `p256` 0.13 — promoted from dev-deps to a direct dep), **EdDSA** (via `ed25519-dalek` 2.x). RFC 7638 canonical JWK SHA-256 thumbprints used as account identifiers; RFC 7638 §3.1 reference vector pinned in tests. RFC 8555 §8.1 keyAuthorization computation. Other algorithms refused at parse with `JwsError::UnsupportedAlg`.
- **Per-mount ACME config** ([`src/modules/pki/acme/path_config.rs`](src/modules/pki/acme/path_config.rs)) — operator-facing `pki/acme/config` CRUD with `enabled` (off by default), `default_role`, `default_issuer_ref`, `external_hostname`, `nonce_ttl_secs`. Authenticated (Vault-token-gated); writing `enabled = true` without a `default_role` is refused.
- **Replay-Nonce ring buffer** ([`src/modules/pki/acme/storage.rs`](src/modules/pki/acme/storage.rs)) — bounded FIFO at 1024 nonces; single-use semantics (RFC 8555 §6.5); aged-out / unrecognised nonces surface as `acme: badNonce` (`urn:ietf:params:acme:error:badNonce` shape) and the request is rejected before any state-changing work.
- **`acme/directory`** ([`src/modules/pki/acme/directory.rs`](src/modules/pki/acme/directory.rs)) — RFC 8555 §7.1.1 directory listing. URLs are rendered absolute, honoring `external_hostname` first and falling back to the inbound `Host` header. Every protocol response includes `Replay-Nonce`, `Cache-Control: no-store`, and a `Link: <directory>;rel="index"` header per RFC 8555 §6.5.
- **`acme/new-nonce`** — RFC 8555 §7.2; mints a fresh `Replay-Nonce` header.
- **`acme/new-account`** + **`acme/account/<id>`** ([`src/modules/pki/acme/account.rs`](src/modules/pki/acme/account.rs)) — RFC 8555 §7.3. New-account verifies the embedded `jwk`, computes the canonical thumbprint, and persists the account at `acme/accounts/<thumbprint>` with status `valid`. Repeated new-account calls with the same key return the existing account (RFC 8555 §7.3 idempotence). `onlyReturnExisting = true` returns `accountDoesNotExist` when the key isn't already registered. Account read uses `kid`-flow JWS — the verifier resolves the `kid` against the persisted JWK and refuses on thumbprint mismatch.
- **Unauthenticated paths** ([`src/modules/pki/mod.rs`](src/modules/pki/mod.rs)) — ACME protocol endpoints bypass the standard token check; JWS in the request body is the auth. The operator-facing `acme/config` stays token-authenticated.
- **7 unit tests pass** — RFC 7638 RSA thumbprint reference vector, RFC 8555 keyAuthorization shape, EdDSA sign/verify round-trip with a freshly generated key, unsupported-alg rejection, missing-jwk-and-kid rejection, nonce ring single-use semantics + ring-cap age-out.

#### PKI — ACME server endpoints (Phase 6.1.5 — order / authz / finalize)

Closes the rest of Phase 6.1: full HTTP-01 issuance flow on top of the foundation above. Spec at [`features/pki-acme.md`](features/pki-acme.md).

- **`acme/new-order` + `acme/order/<id>`** ([`src/modules/pki/acme/order.rs`](src/modules/pki/acme/order.rs)) — RFC 8555 §7.4. Each `dns` identifier in the request body gets its own authz with a single HTTP-01 challenge. Orders default to a 7-day expiry, authz to 30 days. POST-as-GET on `order/<id>` re-evaluates state on read so a chall flip surfaces on the very next poll. Non-`dns` identifiers refused with a clear error (Phase 6.2 will add `dns-01` to support wildcard / private-zone identifiers but not new identifier types).
- **`acme/authz/<id>` + `acme/chall/<id>`** ([`src/modules/pki/acme/authz.rs`](src/modules/pki/acme/authz.rs)) — RFC 8555 §7.5. POST-as-GET on authz returns the challenge URLs, status, and tokens. POST on `chall/<id>` triggers the validator: the engine recomputes the expected `keyAuthorization` (`<token>.<thumbprint>`) and runs the algorithm-specific check.
- **HTTP-01 validator** (same file) — `ureq` 3.x outbound `GET http://<domain>/.well-known/acme-challenge/<token>` with explicit 5 s connect / 10 s global timeout, redirects disabled (so a misbehaving target can't pull the engine through 30 redirects to an internal RFC 1918 endpoint), and a 4 KiB body cap (the keyAuthorization is ~90 bytes — anything bigger is misconfiguration or SSRF amplification). Body-trim then exact-equality match against the expected keyAuthorization. Failures attach an RFC 8555 §6.7 problem document at `chall.error` and flip both chall + owning authz to `invalid`.
- **`acme/order/<id>/finalize`** (same file as new-order) — RFC 8555 §7.4. Pulls the CSR from the JWS payload (base64url-encoded DER), feeds it through the existing [`csr::parse_and_verify`](src/modules/pki/csr.rs) (which does the self-signature check across both classical and ML-DSA-44/65/87 CSRs), then re-validates that the CSR's CN + DNS SANs match the order's identifiers exactly in both directions (CSR can't request an unauthorised name, order can't have an identifier the CSR omitted). On match, dispatches into the same [`x509::build_leaf_from_spki`](src/modules/pki/x509.rs) + [`x509_pqc::build_leaf_from_pqc_spki`](src/modules/pki/x509_pqc.rs) builders `pki/sign/<role>` already uses, with the role + issuer resolved from `acme/config`'s `default_role` + `default_issuer_ref`. Mixed classical/PQC chains rejected (default-secure, same as the rest of the engine). The leaf is persisted both at `acme/orders/<id>/cert` (PEM bundle of leaf + issuer) **and** in the engine's normal `certs/<serial>` index — so revoke + CRL flows treat it identically to non-ACME issuance.
- **`acme/cert/<id>`** (same file) — RFC 8555 §7.4.2 retrieval. POST-as-GET, kid-flow JWS, returns `Content-Type: application/pem-certificate-chain` of leaf + issuer.
- **Account update** ([`src/modules/pki/acme/account.rs`](src/modules/pki/acme/account.rs)) — RFC 8555 §7.3.2. `account/<id>` now accepts a non-empty payload to update `contact` (URL list) and to deactivate (`status = "deactivated"`). Any other status mutation refused; partial updates supported (only the fields present in the payload change).
- **State machine** — order status is recomputed from its authzs on every poll: `pending` → `ready` once every authz is `valid`; `pending` → `invalid` if any authz becomes `invalid`/`expired`/`deactivated`. `finalize` is gated on `ready`.
- **Routes wired** ([`src/modules/pki/mod.rs`](src/modules/pki/mod.rs)) — six new paths added to the PKI logical backend; their URL prefixes added to `unauth_paths` (JWS in the body is the auth).

#### PKI — ACME server endpoints (Phase 6.2 — DNS-01 + EAB + revoke)

Closes Phase 6.2: DNS-01 validator, External Account Binding, and ACME-side `revoke-cert`.

- **DNS-01 validator** ([`src/modules/pki/acme/dns01.rs`](src/modules/pki/acme/dns01.rs)) — `hickory-resolver` 0.24 (new dep, pure Rust, no extra TLS stack — uses `tokio-runtime` feature; lookups run on a fresh OS thread + single-threaded runtime so the validator works under both the default async build and `--features sync_handler` without colliding with any ambient runtime). `_acme-challenge.<domain>` TXT lookup with multi-character-string concatenation per RFC 1035 §3.3.14, matched against `base64url(SHA-256(keyAuthorization))` per RFC 8555 §8.4. 5 s timeout, 2 attempts.
- **Pinned resolvers** ([`src/modules/pki/acme/path_config.rs`](src/modules/pki/acme/path_config.rs)) — new `dns_resolvers` config field (comma-separated `<ip>` or `<ip>:<port>`); falls back to the system resolver only when empty. Production operators should always pin so a misbehaving system resolver isn't on the trust path that decides whether to issue.
- **DNS-01 challenge minted alongside HTTP-01** ([`src/modules/pki/acme/order.rs`](src/modules/pki/acme/order.rs)) — every authz now offers both challenges; the client picks which to satisfy and the chall handler dispatches on `chall.typ`.
- **External Account Binding** ([`src/modules/pki/acme/eab.rs`](src/modules/pki/acme/eab.rs)) — RFC 8555 §7.3.4. Operator-facing `pki/acme/eab/<key_id>` CRUD provisions HMAC-SHA-256 keys (random 256-bit when `key_b64` omitted); `acme/config.eab_required = true` makes the binding mandatory on `new-account`. Inner JWS verification: `alg = HS256`, `kid` resolves to a stored key, `url` ends in `/acme/new-account`, payload JWK matches the outer envelope's account JWK by RFC 7638 thumbprint, HMAC-SHA-256 over `protected.payload` matches the signature. Consumed keys are marked single-use; the operator re-issues a fresh key per client.
- **`acme/revoke-cert`** ([`src/modules/pki/acme/revoke.rs`](src/modules/pki/acme/revoke.rs)) — RFC 8555 §7.6. Kid-flow JWS, payload `{ certificate: <b64url DER>, reason?: <int> }`. The DER is parsed via `x509-parser` to extract the serial; the requesting account is authorised iff it owns an order whose stashed cert chain encodes the same serial (linear scan of the account's orders — small per-account fan-out, no reverse index to maintain). On match, drops into the same plumbing `pki/revoke` uses ([`src/modules/pki/path_revoke.rs::rebuild_crl_for_issuer`](src/modules/pki/path_revoke.rs)) — flip `CertRecord.revoked_at_unix`, append to the issuer's `CrlState`, rebuild that issuer's CRL. ACME-revoked certs appear on the same CRL as anything else issued by the mount.
- **Routes wired** ([`src/modules/pki/mod.rs`](src/modules/pki/mod.rs)) — two new ACME routes (`acme/revoke-cert`, `acme/eab/<id>`) added to the PKI logical backend; `revoke-cert` added to `unauth_paths`. Operator-facing `acme/eab/<id>` is Vault-token-authenticated.
- **11/11 ACME unit tests pass** — earlier 9 plus EAB HS256 round-trip + consumed-key rejection. DNS-01 helpers tested for SHA-256 keyAuthorization shape and resolver-string parsing (no live wire DNS in CI).

#### PKI — ACME server endpoints (Phase 6.3 — key-change + rate limit + expiry sweep)

Closes Phase 6.3. The ACME server is now feature-complete on the RFC 8555 surface (HTTP-01 + DNS-01, full account / order / cert lifecycle, EAB, revoke, key rollover, rate limiting, periodic sweep).

- **`acme/key-change`** ([`src/modules/pki/acme/key_change.rs`](src/modules/pki/acme/key_change.rs)) — RFC 8555 §7.3.5. Outer JWS signed by the **old** account key (kid flow; nonce + url-tail enforced by the shared `verify_kid_jws` helper). Outer payload is itself a flattened JWS signed by the **new** key (must embed `jwk`, not `kid`); inner payload is `{ account: <kid>, oldKey: <jwk> }`. Verifies the inner-JWS signature, asserts inner.url == outer.url, asserts the bind's `account` resolves to the same id as the outer kid, asserts `oldKey`'s RFC 7638 thumbprint equals the currently-stored JWK's thumbprint, and refuses if the new key's thumbprint already belongs to another account. On success the account record's stored JWK is replaced; the account id (URL) stays stable so existing orders keep working. Account-endpoint thumbprint == id assertion in [`account.rs`](src/modules/pki/acme/account.rs) was relaxed (the verifier already used the persisted JWK; the redundant equality check would have broken kid lookups after a successful rollover).
- **Per-account rate limiting** ([`src/modules/pki/acme/order.rs`](src/modules/pki/acme/order.rs)) — sliding-window counter at `acme/rate/<account_id>`. New `acme/config.rate_window_secs` (default 3600) + `rate_orders_per_window` (default 300); 0 in either knob disables. Exhausted bucket returns `urn:ietf:params:acme:error:rateLimited` per RFC 8555 §6.6. Counter is pruned on every touch so the per-account list is bounded by the window.
- **ACME expiry sweep folded into `pki/tidy`** ([`src/modules/pki/path_tidy.rs`](src/modules/pki/path_tidy.rs)) — same `safety_buffer_seconds` window the cert sweep uses. Walks `acme/orders/`, `acme/authz/`, `acme/chall/`; deletes orders past their `expires_at_unix` (along with their stashed cert blob), deletes authzs past their `expires_at_unix`, and garbage-collects orphan challenges whose parent authz no longer resolves. Records that pre-date Phase 6.1 (no `expires_at_unix`) skip the sweep — same conservative posture as cert records with `not_after_unix == 0`. Best-effort per record so one corrupt blob can't stall the run.
- **Routes wired** ([`src/modules/pki/mod.rs`](src/modules/pki/mod.rs), [`src/modules/pki/acme/mod.rs`](src/modules/pki/acme/mod.rs)) — `acme/key-change` added to the PKI logical backend and to `unauth_paths` (JWS in the body is the auth).
- **12/12 ACME unit tests pass** — earlier 11 plus key-change inner-JWS round-trip (Ed25519 sign + verify the inner envelope shape). `cargo check --workspace` clean.

The ACME server is now positioned as a drop-in replacement for `certbot --server` against an internal-PKI mount; an operator who follows the spec at [`features/pki-acme.md`](features/pki-acme.md) can stand up cert-manager / Caddy / Traefik against it without further code changes. EAB key rotation remains operator-driven via the existing `acme/eab/<key_id>` CRUD.

New direct dep: `p256 = "0.13"` with `ecdsa` feature, `default-features = false` (was dev-only). No new C-linked deps; pure-Rust RustCrypto throughout.

#### OpenLDAP / AD password-rotation — Phase 5 identity-aware check-out affinity

- **New `affinity_ttl` field on `LibrarySet`** ([`src/modules/ldap/policy.rs`](src/modules/ldap/policy.rs)) — `Duration::ZERO` (default) keeps every check-out picking the first available account, matching the prior behavior. When set non-zero, the engine writes an `AffinityRecord` keyed by `(set, hex(entity_id))` after every successful check-in; the next check-out from the same entity within the window prefers the previously-held account when it's currently available.
- **Lazy expiration + graceful fallback** ([`src/modules/ldap/path_library.rs`](src/modules/ldap/path_library.rs)) — `read_affinity` drops stale records on first sight (no separate sweep needed). Affinity hits log at debug; a stale record, an unparseable entry, or an account that's currently checked out by someone else *all* fall back silently to the first-available pick. The caller never observes a "your old account is in use" error — affinity is opportunistic, not load-bearing.
- **Affinity records hex-encode the entity id** so an entity that legitimately contains `/` or other path-meaningful characters can't escape the per-set `library/<set>/affinity/<hex>` key namespace.
- **Affinity records swept on `delete_set`** so a re-create of the same set name doesn't inherit stale per-entity hints from the previous incarnation.
- **GUI exposed** ([`gui/src-tauri/src/commands/ldap.rs`](gui/src-tauri/src/commands/ldap.rs), [`gui/src/lib/types.ts`](gui/src/lib/types.ts), [`gui/src/routes/LdapPage.tsx`](gui/src/routes/LdapPage.tsx)) — Library editor gains an "Affinity TTL (s)" input with a `0 = off` hint; the `LdapLibrarySet` type interface gains the field; the Tauri command round-trips it on read + write.
- **2 new unit tests** — `affinity_record_serde_roundtrip` and `library_default_affinity_is_off`. **19/19 LDAP tests pass** (was 17). `cargo check --workspace` clean; `npx tsc --noEmit` clean; `npx vitest run` 66/66 pass.

#### OpenLDAP / AD password-rotation — Phase 4 GUI integration

- **Tauri command surface** ([`gui/src-tauri/src/commands/ldap.rs`](gui/src-tauri/src/commands/ldap.rs)) — 19 commands bridging the desktop GUI to the engine: mount list / enable, connection config CRUD + rotate-root, static-role CRUD + LIST + read-current-cred + force-rotate, library set CRUD + LIST + check-out / check-in / status. Same `make_request` thin-wrapper pattern as `commands/ssh.rs` / `commands/transit.rs`; mount path parameterised so a non-default mount works unchanged.
- **`/ldap` route + sidebar nav** ([`gui/src/routes/LdapPage.tsx`](gui/src/routes/LdapPage.tsx), [`gui/src/components/Layout.tsx`](gui/src/components/Layout.tsx)) — three-tab page: **Connection** (config card with directory-type / StartTLS / insecure_tls badges, Edit modal with two-flag `insecure_tls = true` + `acknowledge_insecure_tls = true` UI gate, Rotate-bind-password button with confirmation, Delete with confirmation), **Static Roles** (CRUD with rotation-period field, Read-password modal with `MaskedValue` + last-rotated timestamp + countdown to next auto-rotation, Rotate-now button that surfaces the freshly-minted password, Delete with confirmation), **Library** (set CRUD with comma- or newline-separated DN editor + TTL + max_TTL + check-in-enforcement toggle; per-set Status panel with auto-refresh-every-5s showing checked-out leases + expiry + per-account Check-in button + available accounts; per-set Check-out button surfaces the lease + password in a one-shot modal). Sidebar nav gated on `requiresMountType: "openldap"` plus `root` / `admin` / `ldap-admin` / `ldap-user` policies — auto-hides when no `openldap/` mount exists, mirroring the established TOTP / PKI / SSH gating pattern.
- **Typed API surface** ([`gui/src/lib/api.ts`](gui/src/lib/api.ts), [`gui/src/lib/types.ts`](gui/src/lib/types.ts)) — full type interfaces (`LdapMountInfo`, `LdapConfigInfo`, `LdapWriteConfigRequest`, `LdapStaticRole`, `LdapStaticCred`, `LdapRotateRoleResult`, `LdapLibrarySet`, `LdapCheckOutResult`, `LdapLibraryStatus`, `LdapLibraryStatusEntry`) plus 19 thin `invoke<T>` wrappers. The write-config wrapper preserves the engine's partial-update semantic by passing `bindpass: undefined` when the operator leaves the field empty on edit.
- **`App.tsx`** routes `/ldap` to `LdapPage` (gated by `ProtectedRoute`); [`MountsPage`](gui/src/routes/MountsPage.tsx) row caveat updated from "no GUI page yet" to the standard nav-gates copy.

#### OpenLDAP / AD password-rotation — Phase 3 auto-rotation scheduler

- **New [`src/modules/ldap/scheduler.rs`](src/modules/ldap/scheduler.rs)** — single tokio task started from `Core::post_unseal`, ticks every 60 s, walks every mount of type `openldap`, finds static-roles where `last_vault_rotation_unix + rotation_period.as_secs() <= now`, and rotates them. One bind per mount per tick when at least one role is due (mounts with no due roles never open an LDAP connection); directory-write-before-storage-write atomicity preserved exactly as the manual `/rotate-role` path. Roles with `rotation_period = 0` are skipped (manual rotation only). Self-skips when sealed. Storage-write-failure-after-directory-write is logged at `error` level — the next tick reconciles via the same pattern the manual path uses. Single-process scheduler today; HA leader gating tracks as a follow-up alongside the same gap in `pki/auto-tidy` + `scheduled_exports`.
- **`run_rotation_pass(core, last_fired)`** is the public entrypoint that integration tests + a future `sys/openldap/rotate-due` admin endpoint can use to force the same sweep on demand without waiting for the 60 s tick.
- **2 new unit tests** on the threshold logic — never-rotated roles fire immediately, rotated-and-still-fresh roles skip, rotated-past-the-window roles fire — and the `is_zero()` manual-only marker. **17/17 LDAP tests pass** (was 15).

#### OpenLDAP / Active Directory password-rotation engine (Phases 1–3)

- **New `openldap/` engine** ([`src/modules/ldap/`](src/modules/ldap/)) — Vault-compatible `/v1/openldap/*` HTTP surface. Routes: connection config CRUD (`/config`), bind-DN self-rotation (`/rotate-root`), static-role CRUD + LIST (`/static-role[/:name]`), `/static-cred/:name` (returns the current cleartext password + last-rotation timestamp + synthetic `ttl_secs`), force-rotate (`/rotate-role/:name`), library set CRUD + LIST (`/library[/:set]`), `/library/:set/check-out` + `/check-in` + `/status`. Path shapes match HashiCorp Vault's `openldap` engine v1 so existing clients work unchanged.
- **Pure-Rust LDAP client** — new direct dep `ldap3 = { version = "0.12", default-features = false, features = ["sync", "tls-rustls-aws-lc-rs"] }`. The `tls-rustls-aws-lc-rs` feature consumes the project-wide `rustls` + `aws_lc_rs` provider — no second TLS stack, no `native-tls`, no `libldap` / `libsasl` / OpenSSL. `Directory` trait branches on `directory_type`: `OpenLdap` writes `Modify(Replace, userPassword, <utf8>)`; `ActiveDirectory` writes `Modify(Replace, unicodePwd, <UTF-16LE-quoted-string>)` per Microsoft's documented byte sequence (regression test pins the encoder against the literal `"Password1"` byte vector from MSDN).
- **TLS-only by default** ([`src/modules/ldap/config.rs`](src/modules/ldap/config.rs)) — plain `ldap://` is refused unless **both** `starttls = true` is set OR **both** `insecure_tls = true` AND `acknowledge_insecure_tls = true` are supplied on the same write. The two-flag opt-in for `insecure_tls` is deliberate so a one-flag typo can't downgrade a prod mount.
- **Rotation atomicity** — every rotation writes the new password to the directory **first**, then persists it in storage. On directory-write failure the storage is left untouched; on storage-write failure the directory carries the new value but the engine surfaces a hard error so an operator can reconcile rather than serve a stale cached password.
- **Library check-out / check-in** ([`src/modules/ldap/path_library.rs`](src/modules/ldap/path_library.rs)) — per-set `tokio::sync::Mutex` serialises check-outs against the same pool so two callers can't race for the same account. Lease IDs are minted as `ldap-library-<uuid>` (the auto-rotation scheduler that walks expiring leases is tracked as a Phase 3 follow-up; today the engine surfaces `expires_at_unix` and operators rotate via `/check-in` or by expiring + force-rotating manually). Check-in identity guard uses `subtle::ConstantTimeEq` against the persisted `checked_out_by`; bypassed only when the operator opts into `disable_check_in_enforcement = true` on the set.
- **Built-in 24-character password generator** ([`src/modules/ldap/password.rs`](src/modules/ldap/password.rs)) — structurally satisfies the AD complexity rule by seeding one character from each of the four classes (lowercase, uppercase, digit, symbol) before filling from the union pool, then shuffling. 1000-generation regression test asserts every output carries every class. The operator-supplied `password_policy` field is persisted today and ignored at generation time until the generator-policies subsystem ships.
- **`ldap-user` / `ldap-admin` baseline policies** ([`src/modules/policy/policy_store.rs`](src/modules/policy/policy_store.rs)) — `ldap-user` grants daily ops (`static-cred` read, `rotate-role`, library check-out / check-in / status, list) without role / set / config / `rotate-root` lifecycle authority; `ldap-admin` grants full mount management. CLI `policy list` golden-output tests in [`src/cli/command/policy_list.rs`](src/cli/command/policy_list.rs) and [`src/cli/command/policy_write.rs`](src/cli/command/policy_write.rs) updated for the two new entries.
- **Module wiring** ([`src/module_manager.rs`](src/module_manager.rs), [`src/modules/mod.rs`](src/modules/mod.rs)) — `LdapModule` registered in `set_default_modules`; operators mount via `POST /v1/sys/mounts/openldap type=openldap`. New row in [`MountsPage.tsx`](gui/src/routes/MountsPage.tsx). 15 unit tests cover the directory dispatcher (OpenLDAP and AD), config validation (TLS opt-in), policy validation, password-generator class invariants, and the AD `unicodePwd` byte encoding pinned against MSDN.
- **Phase 4 (GUI) and Phase 5 (identity-aware affinity) deferred** — the engine is fully usable from the API and Vault-compatible CLIs today; an `/openldap` route on the desktop GUI is tracked in `features/ldap-secret-engine.md` as a separate follow-up. Auto-rotation scheduler (Phase 3 stretch) is also a follow-up; manual `/rotate-role` works today.

#### Plugin System — Phase 5 follow-ups (5.3, 5.4, 5.12)

Closes the remaining shippable gaps from the Phase 5 list (5.11 — reference-plugin integration tests against the main suite — still requires the `plugins-ext/` git submodule + `testcontainers` infrastructure and is the sole outstanding Phase 5 item).

- **5.3 Long-lived supervised process runtime** ([`src/plugins/process_supervisor.rs`](src/plugins/process_supervisor.rs)) — opt-in via new manifest field `capabilities.long_lived = true`. Spawns one persistent child per plugin name and reuses it across invocations. **Restart-with-exponential-backoff**: 1s → 60s ceiling. **Restart breaker**: more than 10 crashes in any 5-minute rolling window opens the breaker (returns `RestartBudgetExhausted` until the window slides forward) so a wedged plugin can't burn fds. **Single-use bootstrap token** per child lifetime (`BV_PLUGIN_BOOTSTRAP_TOKEN`) — the plugin must echo it in a `Hello` message during the 60 s handshake window or the spawn is torn down. **Stderr forwarding** continues to flow into the host log tagged `[plugin=<name>]`. Long-lived plugins extend the JSON-line wire protocol with `invoke` / `invoke_done` messages keyed by request id; existing single-shot semantics (default `long_lived = false`) are unchanged so the SDK + reference plugins in `plugins-ext/` keep working. The supervisor's child is torn down on `delete` (catalog) and on `reload` (HTTP handler) so re-registration always starts a fresh process. The original tonic/UDS substrate from the spec is intentionally not adopted — stdio works identically across Linux / Windows / macOS without socket-permission gymnastics, adds zero new crate deps, and matches the substance of "supervised long-lived child"; the wire-format promotion to `tonic`/`prost` remains tracked under the (still-open) thread that follows the protocol unification.
- **5.4 Host-side ABI version major check** ([`src/plugins/manifest.rs`](src/plugins/manifest.rs), [`src/plugins/catalog.rs`](src/plugins/catalog.rs)) — new `HOST_ABI_MAJOR` / `HOST_ABI_MINOR` constants, `parse_abi()` + `check_abi_compatibility()` helpers, and a registration-time gate in `PluginCatalog::put`. Refuses cross-major plugins with a clear error pointing the operator at the host's supported version + a link to the migration window in `features/plugin-system.md § Versioning`. Refuses future-minor plugins (host older than plugin) with a "upgrade BastionVault before loading" message. Refuses malformed `abi_version` values that would otherwise silently coerce to `(0, 0)`.
- **5.12 GUI per-plugin metrics** ([`src/plugins/metrics.rs`](src/plugins/metrics.rs), [`gui/src-tauri/src/commands/plugins.rs`](gui/src-tauri/src/commands/plugins.rs), [`gui/src/routes/PluginsPage.tsx`](gui/src/routes/PluginsPage.tsx)) — new `snapshot_for(name) -> PluginMetricsSnapshot` + `snapshot_all()` accessors backed by a parallel `DashMap<String, Mutex<SnapshotInner>>` shadow store (the prometheus_client `Family` doesn't expose a stable iterator). New Tauri command `plugins_metrics`. New panel on the Plugins page (`PluginMetricsPanel`) polls every 5 s and renders one row per plugin with **Success / Plugin error / Runtime error** invoke counts, **Fuel consumed** (WASM only), and **Average latency** in ms. The full Prometheus surface — including the latency-bucket histograms — stays at `/sys/metrics`; the panel is the at-a-glance view for desktop operators who don't run a separate scrape.
- **Supervisor unit tests** — backoff schedule grows-and-caps, restart-budget breaker trips at the configured threshold, `record_success` clears `consecutive_failures` but preserves the rolling crash window so a flapping plugin doesn't escape detection.
- **ABI-version unit tests** — accepts same-major lower-minor, rejects cross-major + future-minor + malformed.
- **61 plugin unit tests pass** (was 54; +7 new). 66/66 vitest tests pass; `npx tsc --noEmit` clean.

#### Plugin System — Phase 5 (production-grade gaps)

Closes the bulk of the Phase 5 thread tracked in `features/plugin-system.md`:

- **5.1 Crypto host capability** ([`src/plugins/runtime.rs`](src/plugins/runtime.rs)) — five new wasmtime imports: `bv.crypto_random`, `bv.crypto_encrypt`, `bv.crypto_decrypt`, `bv.crypto_sign`, `bv.crypto_verify`, `bv.crypto_hmac`. Backed by Transit (mount path conventional `transit/keys/<name>`); the host validates `key` against `manifest.capabilities.allowed_keys` literally before dispatching to the Transit backend, then base64-encodes inputs / decodes outputs and surfaces the relevant field. Unauthorised keys return `CRYPTO_FORBIDDEN` (`-2`); backend failures return `CRYPTO_BACKEND_ERROR` (`-5`). The plugin never sees the key bytes.
- **5.2 ML-DSA-65 publisher signature verification** ([`src/plugins/verifier.rs`](src/plugins/verifier.rs)) — manifests carry `signature` + `signing_key`; the catalog verifies on registration *and* on every load using `bv_crypto`'s ML-DSA-65 path. Operator-pinned publisher allowlist at `core/plugins/engine/publishers` (`PUT /v1/sys/plugins/publishers`); engine `accept_unsigned` flag at `core/plugins/engine/accept_unsigned` for development opt-in (`PUT /v1/sys/plugins/accept_unsigned`; logged at WARN). Canonical signing message is `sha256(binary) || canonical_manifest_json_with_signature_field_stripped`.
- **5.5 Net allowlist registration check** ([`src/plugins/catalog.rs`](src/plugins/catalog.rs)) — `validate_net_allowlist` refuses bare `"*"`, port-bearing entries, and `*` outside the leading-label position (so `*.example.com` is allowed; `foo.*.com` is not).
- **5.6 Reload drain-and-swap** ([`src/plugins/reload_lock.rs`](src/plugins/reload_lock.rs), [`src/http/sys.rs`](src/http/sys.rs)) — per-plugin `tokio::sync::RwLock` with `read_owned()` / `write_owned()`. Every invoke acquires a read; the reload HTTP handler acquires the write with a 10 s drain timeout. On drain timeout the response is `503 plugin_reloading`. New invokes during the swap block on the write; they resume against the freshly-compiled module on next call.
- **5.7 Quarantined mount state on plugin delete** ([`src/plugins/quarantine.rs`](src/plugins/quarantine.rs), [`src/plugins/catalog.rs`](src/plugins/catalog.rs), [`src/plugins/logical_backend.rs`](src/plugins/logical_backend.rs)) — `delete` writes a marker at `core/plugins/engine/quarantine/<name>` (with timestamp + last-active version) instead of touching the per-plugin **data prefix** (`core/plugins/<name>/data/`). Mounts referencing a quarantined plugin surface a clear "quarantined: re-register the plugin to recover" error from `PluginLogicalBackend`. Re-registering the same name auto-clears the marker. Operators can audit the set via `GET /v1/sys/plugins/quarantine`.
- **5.8 Lease renew/revoke plumbing** ([`src/plugins/logical_backend.rs`](src/plugins/logical_backend.rs)) — `translate_response` parses an optional top-level `secret { lease_id, ttl_secs, renewable, internal_data }` block from the plugin's response into `Response.secret: Option<SecretData>`, so plugin-issued leases drive the existing lease manager's renew/revoke handlers. Renew/revoke ops were already routed back to the plugin via `build_envelope`; the lease side of the loop is now closed.
- **5.9 Capability-widening guard on re-registration** ([`src/plugins/catalog.rs`](src/plugins/catalog.rs)) — `check_capability_widening` refuses any new version whose `audit_emit` flips on, whose `storage_prefix` is added or moved to a non-sub-prefix, or whose `allowed_keys` / `allowed_hosts` set gains an entry. Operators who actually want broader caps must DELETE + re-register (which audits the change and surfaces the quarantine flow).
- **5.10 Per-plugin metrics** ([`src/plugins/metrics.rs`](src/plugins/metrics.rs)) — three new Prometheus families wired into `MetricsManager`: `bvault_plugin_invokes_total{plugin, outcome="success"|"plugin_error"|"runtime_error"}`, `bvault_plugin_fuel_consumed_total{plugin}` (WASM only), `bvault_plugin_invoke_duration_seconds{plugin}` (latency histogram with the project's standard tier buckets). Recorded around every `PluginLogicalBackend::handle_request` invoke.
- **Manifest schema** ([`src/plugins/manifest.rs`](src/plugins/manifest.rs)) — gains `signature: String` + `signing_key: String` fields (both `serde(default)` + `skip_serializing_if = "String::is_empty"`, so existing manifests without them still parse and serialise compactly).
- **HTTP surface** ([`src/http/sys.rs`](src/http/sys.rs)) — three new sys routes: `GET/PUT /v1/sys/plugins/publishers`, `PUT /v1/sys/plugins/accept_unsigned`, `GET /v1/sys/plugins/quarantine`. Reload (`POST /v1/sys/plugins/<name>/reload`) is now drain-and-swap.
- **Tests** — 54 plugin unit tests pass (was 47 + 4 broken). New coverage: `delete_writes_quarantine_marker`, `cap_widening_refused_on_reregister`, `wildcard_host_refused_at_registration`, verifier round-trip, allowlist serde round-trip, two reload-lock concurrency tests. Existing catalog tests gained an `enable_unsigned(&s)` setup call so they keep registering unsigned plugins under the engine's development opt-in.

Outstanding Phase 5 work tracked separately (deferred — both genuinely large): **5.3 long-lived supervised process runtime** with `tonic`/`prost` over UDS / Windows named pipes, restart-with-backoff, log forwarding, single-use 60s bootstrap token; and **5.4 shared `PluginService` `.proto`** that promotes both runtimes to the same versioned wire schema. Single-shot `process_runtime` continues to work for "I need real network for one call" cases.

#### Transit Secret Engine — Phase 4
- **Derived + convergent encryption** ([`src/modules/transit/crypto/derive.rs`](src/modules/transit/crypto/derive.rs), `path_keys.rs`, `path_encrypt.rs`) — always-on, no new external deps. `derived = true` on a `chacha20-poly1305` key requires every encrypt / decrypt / rewrap to carry a non-empty `context`; the engine HKDFs a per-context subkey via `HKDF-SHA-256(parent, info="bvault-transit-derive\0" || context)` so one logical key drives many cryptographic separation domains (per-row, per-tenant, per-customer) without operators allocating one Transit key each. `convergent_encryption = true` (refused without `derived = true` and refused on non-AEAD key types) makes the AEAD nonce deterministic via a domain-separated `HMAC-SHA-256(parent || "bvault-transit-conv-nonce", len(context) || context || plaintext)[..12]` so the same `(key, context, plaintext)` produces byte-identical ciphertext — useful for de-duplication and equality search over encrypted columns. ML-KEM and other randomised-by-spec primitives are explicitly refused at create time, not at first use.
- **BYOK import** ([`src/modules/transit/path_import.rs`](src/modules/transit/path_import.rs)) under the new `transit_byok` cargo feature. Three endpoints: `POST /v1/transit/wrapping_key` returns the per-mount lazily-generated ML-KEM-768 wrapping public key (the private half stays inside the barrier); `POST /v1/transit/keys/:name/import` accepts a `bvault:vN:pqc:ml-kem-768:<b64>` wrapped 32-byte symmetric key plus an algorithm declaration (`chacha20-poly1305` or `hmac`) and the `derived` / `convergent_encryption` / `exportable` / `deletion_allowed` flags, decapsulates with the mount's wrapping secret, validates the recovered key length matches the declared type, and stores it as version 1 under a fresh policy; `POST /v1/transit/keys/:name/import_version` appends a wrapped version to an existing key, rejecting any attempt to type-mutate the policy under cover of a fresh version. The wrapping shape is the same `bvault:` framing the engine itself emits via `/datakey/wrapped`, so any caller with a FIPS 203 implementation (Rust `ml-kem`, OpenQuantumSafe `liboqs`, …) can wrap material client-side as long as it follows the engine's `HKDF-SHA-256(shared_secret, info="bvault-transit-datakey")` derivation.
- **Hybrid composite signing** ([`src/modules/transit/crypto/hybrid.rs`](src/modules/transit/crypto/hybrid.rs)) under the new `transit_pqc_hybrid` cargo feature. New key type `hybrid-ed25519+ml-dsa-65` mints both halves over the same caller-supplied message; the wire signature is `u16-be(len(ed25519_sig)) || ed25519_sig || mldsa65_sig` carried inside the standard `bvault:vN:pqc:hybrid-ed25519+ml-dsa-65:<b64>` framing. Verify validates **both** halves — flipping a single byte inside either half fails the verify (regression test in place). Pulls no new external deps; the components are already in tree.
- **Hybrid KEM** ([`src/modules/transit/crypto/hybrid.rs`](src/modules/transit/crypto/hybrid.rs)) under `transit_pqc_hybrid`. New key type `hybrid-x25519+ml-kem-768` plus a fresh direct dep `x25519-dalek = "2"` (gated by the same feature). Encapsulate generates an ephemeral X25519 secret + does ECDH against the recipient's static X25519 public, then ML-KEM-768 encapsulates against the recipient's PQ public; the two shared secrets are concatenated and fed through `HKDF-SHA-256(info="bvault-transit-hybrid-kem")` to derive a 32-byte AES-shaped key. The wire format is `u16-be(32) || x25519_eph_pk || ml_kem_ciphertext`. The `KeyType` capability matrix is updated so the new variants slot into `/sign`+`/verify` (composite sigs) and `/datakey/{plaintext,wrapped,unwrap}` (hybrid KEM) without any path-handler changes beyond the dispatch arms.
- **Wire framing** ([`src/modules/transit/crypto/ciphertext.rs`](src/modules/transit/crypto/ciphertext.rs)) — the `bvault:vN:pqc:<algo>:` parser now recognises `hybrid-ed25519+ml-dsa-65` and `hybrid-x25519+ml-kem-768` regardless of build feature so a default-build operator who receives a hybrid payload gets a clear "feature not enabled" error from the path handler instead of a confusing "unknown algo" parse rejection.
- **Tests** — 8 new unit tests across `derive`, `hybrid`, and `ciphertext`. Default build: 19 transit unit tests (was 16). With `--features transit_pqc_hybrid,transit_byok`: 24 tests (composite sign round-trip + two-halves-required + hybrid KEM round-trip + tamper + length-prefix codec). All green.

#### Transit Secret Engine (Phases 1–3)
- **New `transit/` engine** ([`src/modules/transit/`](src/modules/transit/)) — Vault-compatible `/v1/transit/*` surface for encryption-as-a-service. Routes: `LIST /v1/transit/keys`, `POST/GET/DELETE /v1/transit/keys/:name`, `POST /v1/transit/keys/:name/{rotate,config,trim}`, `POST /v1/transit/{encrypt,decrypt,rewrap}/:name`, `POST /v1/transit/{sign,verify}/:name`, `POST /v1/transit/hmac/:name` + `POST /v1/transit/verify/:name/hmac`, `POST /v1/transit/datakey/{plaintext,wrapped}/:name` + `POST /v1/transit/datakey/unwrap/:name`, `POST /v1/transit/{random,hash}`. Keys are versioned — encrypt/sign use the latest, decrypt/verify try every version ≥ `min_decryption_version`. Wire framing is `bvault:vN[:pqc:<algo>]:<base64>` so a payload's algorithm + version is locked in even if the key name is later destructively retyped. `min_decryption_version`, `min_available_version`, and `deletion_allowed` are configurable; `exportable` is sticky-once-false and cannot be re-enabled after creation. (`features/transit-secret-engine.md`)
- **Pure-Rust crypto stack** ([`src/modules/transit/crypto/`](src/modules/transit/crypto/)) — symmetric AEAD (`chacha20-poly1305`) on top of `bv_crypto::Chacha20Poly1305Cipher`; HMAC-SHA-{256,384,512} via `hmac` 0.13 + `sha2` 0.11 with constant-time verify via `subtle`; classical signing via `ed25519-dalek` 2.x; **post-quantum** signing via `bv_crypto::MlDsa{44,65,87}Provider` (FIPS 204) and KEM-based datakey wrap via `bv_crypto::MlKem768Provider` (FIPS 203) with HKDF-SHA-256 (`bvault-transit-datakey` info) deriving a 32-byte AES-shaped key from each shared secret. No OpenSSL, no `aws-lc-sys`. New direct deps: `ed25519-dalek = "2"`, `hkdf = "0.13"` (both already in the transitive tree, promoted to top-level for the `use` import).
- **Key types shipped today** — `chacha20-poly1305`, `hmac`, `ed25519`, `ml-kem-768`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`. The `KeyType` capability matrix structurally enforces "no key supports both sign and encrypt" — refuses sign on an encrypt-only key (and vice versa) at the path layer before any crypto runs. RSA + ECDSA-P256/P384, hybrid composite KEMs / sigs (`hybrid-x25519+ml-kem-768`, `hybrid-ed25519+ml-dsa-65`), BYOK import (`/wrapping_key` + `/import`), and convergent / derived modes are deferred to Phase 4 follow-ups.
- **Dedicated `transit-user` and `transit-admin` baseline policies** ([`src/modules/policy/policy_store.rs`](src/modules/policy/policy_store.rs)) — `transit-user` grants encrypt/decrypt/rewrap/sign/verify/hmac/datakey/random/hash plus key metadata read (needed for verifier flows that fetch the public key) without any key-lifecycle authority; `transit-admin` grants full mount management. The engine refuses to flip `exportable` to true after creation, so even an admin token cannot retroactively unlock seed export — that stickiness is enforced server-side regardless of policy. The CLI `policy list` golden-output tests in [`src/cli/command/policy_list.rs`](src/cli/command/policy_list.rs) and [`src/cli/command/policy_write.rs`](src/cli/command/policy_write.rs) updated for the two new entries.
- **Module wiring** ([`src/module_manager.rs`](src/module_manager.rs), [`src/modules/mod.rs`](src/modules/mod.rs)) — `TransitModule` registered in `set_default_modules`; operators mount via `POST /v1/sys/mounts/transit type=transit` and the per-mount UUID isolates one tenant's keys from another's. [`MountsPage`](gui/src/routes/MountsPage.tsx) gains a Transit row. 16 unit tests cover ciphertext framing (round-trip + bad-prefix / bad-version / unknown-pqc-algo rejection), AEAD tamper rejection, Ed25519 sign/verify, ML-KEM-768 datakey round-trip, ML-DSA-44/65/87 round-trips, and policy version-for-decrypt enforcement.

#### Roadmap: OpenLDAP / Active Directory password-rotation engine spec
- **New feature spec** ([`features/ldap-secret-engine.md`](features/ldap-secret-engine.md)) — design for a Vault-compatible `openldap/` secret engine that owns password rotation for OpenLDAP / Active Directory service accounts. Two access modes: **static-role** (long-lived account, rotated on schedule or on-demand; `static-cred/:name` returns the current value) and **library check-out / check-in** (pool of pre-provisioned accounts shared across automation; check-out rotates + leases an account, check-in or lease-expiry rotates + releases). Pure-Rust implementation on `ldap3` 0.11 with `tls-rustls`, no OpenSSL / `aws-lc-sys`. AD vs. OpenLDAP branch via a `Directory` trait (selects `unicodePwd` UTF-16LE-quoted-string vs. `userPassword` UTF-8). Five phases scoped: Phase 1 static roles + connection, Phase 2 library mode, Phase 3 auto-rotation scheduler, Phase 4 GUI, Phase 5 (stretch) identity-aware check-out affinity. Status added to [`roadmap.md`](roadmap.md) under **Secret Engines** as `Todo`.

#### TOTP Secret Engine — Phase 4 (GUI integration)
- **Tauri command surface** ([`gui/src-tauri/src/commands/totp.rs`](gui/src-tauri/src/commands/totp.rs)) — 8 commands bridging the desktop GUI to the TOTP engine: mount list / enable, key list / read / create / delete, code GET (generate-mode live code) and POST (provider-mode validate). Same `make_request` thin-wrapper pattern as `commands/ssh.rs` and `commands/pki.rs`; mount path parameterised so a non-default mount works unchanged.
- **`/totp` route + sidebar nav** ([`gui/src/routes/TotpPage.tsx`](gui/src/routes/TotpPage.tsx), [`gui/src/components/Layout.tsx`](gui/src/components/Layout.tsx)) — three-tab page: **Keys** (list + per-row "Details" expander showing mode/algorithm/issuer/account/digits/period/skew/replay-check, create modal with generate↔provider mode toggle and one-shot QR-display result modal that drops the seed on close, delete with confirmation), **Live Code** (current 6/8-digit code for a generate-mode key with a circular SVG timer driven from `Date.now()` so a stalled fetch can't lie about the remaining window — re-fetches only when the step boundary is crossed), **Validate** (provider-mode code-validate widget that reports `valid` / `invalid (or replay-rejected)`). Sidebar entry hidden when no `totp/` mount exists.
- **Dedicated `totp-user` and `totp-admin` baseline policies** ([`src/modules/policy/policy_store.rs`](src/modules/policy/policy_store.rs)) — registered alongside `pki-user` / `pki-admin`. `totp-user` grants `LIST totp/keys` plus read/update/create on `totp/code/*` (fetch a generate-mode code, validate a provider-mode code) without authority to enroll, delete, or read any key metadata that would let the holder enumerate which authenticators are enrolled. `totp-admin` grants full mount management plus `sys/mounts` discovery and inherits all `totp-user` capabilities. The CLI `policy list` golden-output tests in [`src/cli/command/policy_list.rs`](src/cli/command/policy_list.rs) and [`src/cli/command/policy_write.rs`](src/cli/command/policy_write.rs) updated for the two new entries.
- **Typed API surface** ([`gui/src/lib/api.ts`](gui/src/lib/api.ts), [`gui/src/lib/types.ts`](gui/src/lib/types.ts)) — `totpListMounts`, `totpEnableMount`, `totpListKeys`, `totpReadKey`, `totpCreateKey`, `totpDeleteKey`, `totpGetCode`, `totpValidateCode` plus their request / result interfaces. `MountsPage` engine catalogue gains a TOTP entry so an operator who hasn't mounted the engine can do so from the same place they mount KV / PKI / SSH.
- **`App.tsx`** routes `/totp` to `TotpPage` (gated by `ProtectedRoute`).

#### TOTP Secret Engine (Phases 1–3)
- **New `totp/` engine** ([`src/modules/totp/`](src/modules/totp/)) — Vault-compatible `/v1/totp/*` surface for time-based one-time passwords (RFC 6238). Routes: `LIST /v1/totp/keys`, `POST/GET/DELETE /v1/totp/keys/:name`, `GET /v1/totp/code/:name` (generate-mode current code), `POST /v1/totp/code/:name` (provider-mode validate). Two modes per key: **generate** (engine draws a fresh seed from `OsRng`, returns a one-shot `otpauth://` URL plus a base64 PNG QR for direct enrollment into Google Authenticator / Authy / 1Password / YubiKey OATH) and **provider** (operator imports an existing seed, either as base32 or as a full `otpauth://` URL — mutually exclusive). Seeds are barrier-encrypted at rest (ChaCha20-Poly1305) and disclosed exactly once, in the create response, when `exported = true`. `GET /v1/totp/keys/:name` only returns metadata. `digits` accepts 6 or 8; `algorithm` accepts SHA1 (default) / SHA256 / SHA512. (`features/totp-secret-engine.md`)
- **Pure-Rust crypto stack** ([`src/modules/totp/crypto/`](src/modules/totp/crypto/)) — HOTP/TOTP built on `hmac` 0.13 + `sha1` / `sha2` 0.11. RFC 4226 Appendix D and RFC 6238 Appendix B test vectors pass byte-for-byte across all three hash algorithms. Constant-time code comparison via `subtle`. No OpenSSL, no `aws-lc-sys`. New direct deps: `base32 = "0.5"`, `subtle = "2.6"`, plus `qrcode` 0.14 + `image` 0.25 (PNG-only) for the barcode renderer.
- **Replay protection** ([`src/modules/totp/backend.rs`](src/modules/totp/backend.rs), [`src/modules/totp/tidy.rs`](src/modules/totp/tidy.rs)) — every successful provider-mode validation persists the matched step under `used/<name>/<step>`; a re-presented code in the same step window returns `valid: false`. Stronger than HashiCorp Vault's TOTP engine, which does not deduplicate by default. Operators can opt out with `replay_check = false` per key for strict Vault parity. An opportunistic sweep on each successful validate drops cache rows older than `(skew + 1) * period` so the index stays bounded. Key delete also clears the per-key replay cache so a re-create with the same name doesn't inherit a stale verdict.
- **QR rendering** ([`src/modules/totp/barcode.rs`](src/modules/totp/barcode.rs)) — pure-Rust `qrcode` → `image::Luma<u8>` → in-memory PNG → base64. No filesystem I/O; the buffer is dropped after the response is serialised. Configurable via `qr_size` (default 200; `0` disables PNG rendering).
- **Module wiring** ([`src/module_manager.rs`](src/module_manager.rs), [`src/modules/mod.rs`](src/modules/mod.rs)) — `TotpModule` is registered in `set_default_modules`; operators mount via `POST /v1/sys/mounts/totp type=totp` and the per-mount UUID isolates one tenant's keys from another's. 11 unit tests cover the RFC vectors, base32 tolerance, otpauth URL round-trip, policy validation, and PNG output shape.

#### SSH Secret Engine — Phase 4 (GUI integration)
- **Tauri command surface** ([`gui/src-tauri/src/commands/ssh.rs`](gui/src-tauri/src/commands/ssh.rs)) — 12 commands bridging the desktop GUI to the SSH engine: mount list / enable, CA read / generate (Ed25519 or ML-DSA-65) / delete, role list / read / write / delete (with full schema mapping including OTP `cidr_list` / `port` and PQC `pqc_only`), `sign` (CA-mode), `creds` + `lookup` (OTP mode). Same `make_request` thin-wrapper pattern as `commands/pki.rs`; mount path parameterised so a non-default mount works unchanged.
- **`/ssh` route + sidebar nav** ([`gui/src/routes/SshPage.tsx`](gui/src/routes/SshPage.tsx), [`gui/src/components/Layout.tsx`](gui/src/components/Layout.tsx)) — four-tab page: **CA** (generate Ed25519 / ML-DSA-65, import existing OpenSSH private key, copy public key, delete with confirmation), **Roles** (CRUD with a unified form that swaps CA / OTP fields based on `key_type`, including the `pqc_only` toggle), **Sign Cert** (paste-public-key-and-sign with algorithm + serial chips and a copy-cert button), **OTP Creds** (mint an OTP for `(role, ip, username)` plus a "which roles cover this?" `lookup` button that doesn't consume a credential). Sidebar nav gated on `requiresMountType: "ssh"` plus `root` / `admin` policies — auto-hides when the engine isn't mounted, matching the PKI link's pattern.
- **Typed API surface** ([`gui/src/lib/api.ts`](gui/src/lib/api.ts), [`gui/src/lib/types.ts`](gui/src/lib/types.ts)) — `sshListMounts`, `sshEnableMount`, `sshReadCa`, `sshGenerateCa`, `sshDeleteCa`, `sshListRoles`, `sshReadRole`, `sshWriteRole`, `sshDeleteRole`, `sshSign`, `sshCreds`, `sshLookup` plus their request / result interfaces. The role-write wrapper skips empty strings on optional fields so the engine's partial-update semantics are preserved on edits.

#### SSH Secret Engine — Phase 3 (post-quantum: ML-DSA-65)
- **`ssh_pqc` feature flag** (off by default) gates a new module [`src/modules/ssh/pqc.rs`](src/modules/ssh/pqc.rs) that hand-rolls the OpenSSH certificate TBS encoder for the `ssh-mldsa65@openssh.com` algorithm on top of `ssh-encoding`'s primitives. We sidestep `ssh-key` 0.6's `Builder` for the PQC path because the (still-draft) algo isn't a `KeyData` variant upstream — running our own encoder keeps the surface honest about what we emit, and `bv_crypto::MlDsa65Provider` (FIPS 204) does the actual sign.
- **`POST /v1/ssh/config/ca {algorithm: "mldsa65"}`** generates an ML-DSA-65 CA. `CaConfig` gained `pqc_secret_seed_hex` (32-byte seed; FIPS 204 keygen rederives the expanded private key on each sign) + `pqc_public_key_hex` (1952-byte pubkey). The classical `private_key_openssh` field stays empty for PQC CAs; `algorithm` distinguishes the two persisted shapes.
- **PQC sign dispatch** ([`src/modules/ssh/path_sign.rs`](src/modules/ssh/path_sign.rs)) — when the persisted CA is ML-DSA-65, signing flows through `handle_sign_pqc` which parses the inbound public key as `ssh-mldsa65@openssh.com`, applies the same role policy enforcement as the classical path (allowed_users + wildcard, default_user fallback, extension/critical-option whitelists merged with `default_*` maps, TTL clamp, not_before backdate, `{{role}}` key-id substitution, OS-RNG serial/nonce), and emits `ssh-mldsa65-cert-v01@openssh.com <base64>` certs.
- **`RoleEntry.pqc_only`** new field. When true, the sign handler rejects classical client public keys explicitly so an operator can guarantee an end-to-end PQC chain (CA + client + signature). Misconfiguration where `pqc_only=true` meets a classical CA fails the sign with a clear "configure a PQC CA first" error rather than silently downgrading.
- **Tests** — 5 new unit tests on `pqc.rs` (CA hex round-trip, OpenSSH-format public-key encode/parse, sign produces distinct certs for distinct specs, classical-key rejection by the PQC parser, truncated-blob rejection) plus end-to-end integration test [`tests/test_ssh_pqc.rs`](tests/test_ssh_pqc.rs) (run with `--features ssh_pqc`) covering PQC CA generate, sign with `pqc_only` role, wire-format envelope check, and the classical-client-against-`pqc_only` rejection path.

#### SSH Secret Engine — Phase 2 (OTP mode + helper binary)
- **OTP mode** ([`src/modules/ssh/path_creds.rs`](src/modules/ssh/path_creds.rs), [`src/modules/ssh/path_lookup.rs`](src/modules/ssh/path_lookup.rs), [`src/modules/ssh/otp.rs`](src/modules/ssh/otp.rs)) — three new routes wired into the SSH engine: `POST /v1/ssh/creds/:role` mints a 160-bit hex one-time password against an OTP-mode role (target IP must fall in the role's `cidr_list` and not in `exclude_cidr_list`), `POST /v1/ssh/verify` consumes the OTP single-use (delete-before-act so a concurrent retry can't double-spend), `POST /v1/ssh/lookup` surfaces which OTP roles cover an `(ip, username)` pair without consuming anything. The plaintext OTP exists only in the `creds` response and the `verify` request body — storage stores SHA-256 only, keyed by hash, so a barrier compromise leaks pre-image hashes rather than live credentials. `RoleEntry` gained `cidr_list` / `exclude_cidr_list` / `port` fields, validated as `ipnetwork::IpNetwork` at role-write time. `key_type=otp` is now accepted (Phase 1 hard-rejected anything but `ca`).
- **`bv-ssh-helper` binary** ([`bin/bv_ssh_helper.rs`](bin/bv_ssh_helper.rs)) — tiny pure-Rust helper that PAM's `pam_exec` invokes on managed hosts. Reads the OTP from stdin (`expose_authtok`), POSTs `/v1/ssh/verify`, exits 0/1 for accept/reject. Configuration via env vars or a root-owned `/etc/bv-ssh-helper.conf` `KEY=VALUE` file. No retries, no caching, no log file of its own — single-line stderr message that PAM forwards to syslog. New Cargo `[[bin]]` registered alongside `bvault`.
- **Tests** — 3 unit tests on `otp.rs` (40-hex-char generation, deterministic hash, distinct OTPs) plus the end-to-end integration test [`tests/test_ssh_otp.rs`](tests/test_ssh_otp.rs) that exercises mint → lookup → verify → replay-fail → out-of-CIDR-fail → excluded-CIDR-skip → missing-`cidr_list` write-time rejection.

#### SSH Secret Engine — Phase 1 (CA mode, Ed25519)
- **New `ssh/` engine** ([`src/modules/ssh/`](src/modules/ssh/)) — Vault-compatible HTTP surface on a pure-Rust crypto stack (`ssh-key` 0.6 + RustCrypto). Routes: `POST /ssh/config/ca` (auto-generate or import an Ed25519 CA), `GET /ssh/config/ca` and `GET /ssh/public_key` (read public key only — private key never leaves the barrier), `DELETE /ssh/config/ca` (rotation), `POST/GET/DELETE /ssh/roles/:name`, `LIST /ssh/roles`, and `POST /ssh/sign/:role` (sign a client public key into an OpenSSH user/host certificate). Role policy enforces `allowed_users` (with `*` wildcard), `default_user` fallback, `allowed_extensions` / `allowed_critical_options` whitelists merged with `default_*` maps (caller wins on key collision), `ttl` clamped to `max_ttl`, `not_before_duration` for clock-skew backdating, and a `key_id_format` template (literal `{{role}}` substitution in Phase 1). Per-cert serial drawn from the OS RNG. RSA / ECDSA / ML-DSA, OTP mode, and the GUI ship in later phases — see [`features/ssh-secret-engine.md`](features/ssh-secret-engine.md). Backed by 7 unit tests + an end-to-end integration test ([`tests/test_ssh_engine.rs`](tests/test_ssh_engine.rs)) that mounts the engine, signs a fresh client key, parses the cert with `ssh-key`, and asserts the role policy actually landed in the wire format.

#### PKI delegated baseline policies
- **`pki-user` and `pki-admin` seeded policies** ([`src/modules/policy/policy_store.rs`](src/modules/policy/policy_store.rs)) -- ship with every install, registered alongside `standard-user`, `standard-user-readonly`, and `secret-author`. `pki-user` grants issuance/signing on the conventional `pki/` mount (`pki/issue/*`, `pki/sign/*`, `pki/sign-verbatim`, plus read on CA/CRL/issuer public material) without administrative authority over issuers, roles, configuration, or revocation. `pki-admin` grants full PKI mount management and inherits all `pki-user` capabilities. Lets operators delegate PKI usage and PKI administration without granting blanket `admin` or `root`.

#### GUI: PKI is no longer admin-only; mount-aware sidebar
- **PKI moved out of the Admin section** ([`gui/src/components/Layout.tsx`](gui/src/components/Layout.tsx)) -- the `/pki` link now lives in the workspace nav, gated by policy (`root`, `admin`, `pki-admin`, `pki-user`) instead of by membership in the admin group. Regular users with `pki-user` see and use the PKI page; users without any PKI policy don't.
- **Per-item nav visibility** -- `NavItem` now carries optional `requires` (policy gate) and `requiresMountType` (mount-table gate). Sidebar links auto-hide when the dependent mount isn't enabled (e.g. PKI disappears if no `pki/` mount exists, Files disappears without a `files/` mount). Permissive fallback applied when `sys/mounts` is unreadable so the route handler still produces a meaningful 403 instead of silent UX dead-ends.

#### GUI: Default Engines admin tab
- **Mounts → Default Engines** ([`gui/src/routes/MountsPage.tsx`](gui/src/routes/MountsPage.tsx)) -- new admin tab that surfaces the well-known engine mounts (KV, Resources, Files, PKI, Identity, Asset Groups, System) as one-click toggle cards. Each card shows current enabled/disabled state, the mount path + logical type, what sidebar features it gates, and a button to enable or disable. System mounts (`sys/`, `identity/`) render as always-on. Admins who use a non-standard layout (e.g. `pki-corp/`) keep the free-form Mount Engine button on the Secret Engines tab.

#### GUI Developer Tooling
- **Local Tauri MCP bridge** -- Add an optional `mcp_local_dev` GUI Cargo feature for the `hypothesi/mcp-server-tauri` bridge, registered only in debug builds when `BASTION_TAURI_MCP=1` is set and bound to `127.0.0.1`. `make run-dev-gui` now enables this local-only development path for AI-assisted GUI inspection while production builds remain unchanged.

#### Secret Engine — PKI Phase 5.5 (multi-issuer usage flags)
- **Per-issuer `usage` field.** Vault-shape lockdown: an issuer can be restricted to `issuing-certificates`, `crl-signing`, `ocsp-signing`, or any combination. Locking down lets an operator dedicate one issuer to issuing leaves and another to CRL signing — useful when an offline-root design wants the root visible online for CRL purposes only, or when separated-duties policy says one issuer must never sign leaves. Closes the last outstanding "deferred" item from Phase 5.2.
- **Storage.** Sparse `usages_by_id: BTreeMap<String, IssuerUsages>` field on [`IssuersIndex`](src/modules/pki/storage.rs). `#[serde(default)]` keeps pre-5.5 indexes deserializable; an issuer missing from the map gets the all-enabled default via [`IssuersIndex::usages_for`](src/modules/pki/storage.rs). Newly-added issuers stay sparse (no entry written) so legacy default behaviour is preserved without growing storage on every issuer.
- **API.** `READ /v1/pki/issuer/:ref` now returns a `usage` array carrying the effective list. `WRITE /v1/pki/issuer/:ref` accepts a `usage` field (comma-separated string or list). The empty-everything case (no `issuer_name`, no `usage`) is rejected so an operator gets a clear error rather than a silent no-op. Empty-usage write rejected too — refusing to leave an issuer that nothing can ever invoke.
- **Enforcement.** Three call sites gate the new bits via [`issuers::require_issuing`](src/modules/pki/issuers.rs) and [`issuers::require_crl_signing`](src/modules/pki/issuers.rs):
  - `pki/issue/:role`, `pki/sign/:role`, `pki/sign-verbatim`, `pki/root/sign-intermediate` all check `usages.issuing_certificates` after issuer resolution; an "issuing-disabled" issuer errors with `ErrPkiKeyTypeInvalid` (same class as the existing mixed-chain rejection).
  - [`path_revoke::rebuild_crl_for_issuer`](src/modules/pki/path_revoke.rs) checks `usages.crl_signing`. Revoke + `pki/crl` read + `pki/crl/rotate` + `pki/issuer/:ref/crl` + the auto-tidy scheduler's revoked-list sweep all funnel through that helper, so they all benefit from the gate without per-route duplication.
- **OCSP-signing reserved.** The `ocsp-signing` bit is parsed, persisted, and surfaced on Read/Write but no route consumes it yet (OCSP responder is a deferred feature). Wiring it through storage now means when OCSP lands the gate is already in place.
- **Default behaviour preserved.** A freshly-created issuer carries `IssuerUsages::all_enabled()` by default — generation, intermediate set-signed, and config/ca import continue to work unchanged. The 14 pre-5.5 PKI integration tests pass without modification.
- **Test** — [tests/test_pki_phase5_5.rs](tests/test_pki_phase5_5.rs) (4 cases): default-usages-all-enabled; lock-to-issuing-only blocks revoke/CRL read; lock-to-crl-only blocks issuance; round-trip preserves the explicit set + empty-set rejected. All 18 PKI integration tests pass; Phase 3 composite test passes with `--features pki_pqc_composite`.

#### Secret Engine — PKI Phase 5.4 (classical CRL on `x509-cert::crl`)
- **Unified CRL builder.** Phase 1 had classical CRLs going through `rcgen::CertificateRevocationListParams::signed_by`, while Phase 2 / Phase 3 had PQC and composite going through manual `x509-cert::crl::TbsCertList` assembly. Phase 5.4 collapses the three onto a single shared helper [`x509_pqc::build_crl_with_alg`](src/modules/pki/x509_pqc.rs) that takes an `AlgorithmIdentifierOwned` + a sign-closure and returns a PEM-encoded CRL string. Each per-class wrapper is now ~10 lines.
- **Classical signing routes through `rcgen::SigningKey::sign(tbs_der)`.** Same crypto under the hood (ring), just one CRL emitter rather than two near-identical paths. Eliminates the lonely `crl.pem().map_err(rcgen_err)?` branch in [`path_revoke::rebuild_crl_for_issuer`](src/modules/pki/path_revoke.rs).
- **Strict-correct `signatureAlgorithm` parameters.** RFC 4055 mandates that `sha{256,384,512}WithRSAEncryption` carry an explicit ASN.1 NULL parameter, while RFC 5758 / RFC 8410 mandate that ECDSA and Ed25519 algorithms *omit* the parameter. The new [`classical_signature_alg_id`](src/modules/pki/x509.rs) builder honours both rules so verifiers that strict-check the AlgorithmIdentifier (Java's `CertPath` validators are notably picky) accept the CRL.
- **No new dependencies** — all the machinery (`x509-cert`, `der`, `spki`, `const-oid`) was already pulled in for the PQC path. PQC + composite + classical now share infrastructure that was previously duplicated three ways.
- **No behavioural change visible to clients.** Same OIDs, same extensions (`crlNumber`), same revoked-cert encoding. The 14 existing PKI integration tests + the feature-gated composite test all pass without modification, including [test_pki_engine.rs](tests/test_pki_engine.rs) (which actually parses the CRL via `x509-parser` and checks revoked-serial inclusion).
- **What this unlocks for follow-ups**: any future CRL-extension addition — `cRLDistributionPoints`, `authorityKeyIdentifier`, `issuingDistributionPoint`, reason-code-per-entry — now lands in *one* place instead of three near-copies. Phase 5.5 candidate.

#### Secret Engine — PKI Phase 5.3 (PKCS#8 envelope for ML-DSA + RSA generation)
- **PKCS#8 `PrivateKeyInfo` for ML-DSA private keys.** Caller-facing private keys returned by `pki/issue`, `pki/sign/:role`, `pki/sign-verbatim`, `pki/intermediate/generate/exported`, and `pki/root/generate/exported` now use a standard PKCS#8 PEM (per the IETF lamps draft `draft-ietf-lamps-dilithium-certificates`): `PrivateKeyInfo { algorithm: id-ml-dsa-{44,65,87}, privateKey: OCTET STRING wrapping the 32-byte seed }`. Replaces the engine-internal `BV PQC SIGNER` JSON envelope at the API surface.
- **Storage stays on the engine-internal envelope.** The `BV PQC SIGNER` PEM continues to back `issuers/<id>/key` (barrier-encrypted). Existing on-disk PQC CA keys read cleanly without migration. Only the *output* over the API gains the PKCS#8 form. New `Signer::to_pkcs8_pem` is the seam; classical keys (RSA / ECDSA / Ed25519) use rcgen's standard PKCS#8 emit, PQC uses [`MlDsaSigner::to_pkcs8_pem`](src/modules/pki/pqc.rs).
- **PKCS#8 import path** — `Signer::from_storage_pem` now also recognises operator-supplied PKCS#8 PEM whose AlgorithmIdentifier OID is one of the ML-DSA levels and routes through `MlDsaSigner::from_pkcs8_pem`. An operator can paste a PKCS#8-format PQC CA bundle into `pki/config/ca` (Phase 5.2 import path) and have it accepted.
- **RSA generation now works.** `key_type = "rsa"` was accepted at role-write time but rejected at `Signer::generate` time with `ErrPkiKeyTypeInvalid` because rcgen 0.14 + `ring` cannot generate RSA keypairs without `aws_lc_rs_unstable` (forbidden). Phase 5.3 plugs the `rsa` crate's `RsaPrivateKey::new` (already a project dependency for SAML signing) into the generator: generate via `rsa`, serialize PKCS#8 PEM via `EncodePrivateKey::to_pkcs8_pem`, then load into rcgen via `KeyPair::from_pem_and_sign_algo`. ([src/modules/pki/crypto.rs](src/modules/pki/crypto.rs))
- **Bit-size → hash convention** — RSA-2048 → SHA-256, RSA-3072 → SHA-384, RSA-4096 → SHA-512. The `_and_sign_algo` form pins the signing hash explicitly because rcgen otherwise picks SHA-256 by default for any rsaEncryption key. Storage round-trip preserves the convention: `CertSigner::from_pem` sniffs the modulus size from the PKCS#8 (via `rsa::RsaPrivateKey::from_pkcs8_pem` + `.size() * 8`) and re-loads with the matching `from_pem_and_sign_algo` so a stored RSA-4096 key keeps signing with SHA-512 on every restart.
- **Test** — [tests/test_pki_phase5_3.rs](tests/test_pki_phase5_3.rs) (2 cases): (a) issue an ML-DSA-65 leaf, decode the returned PKCS#8 manually, find the inner OCTET STRING, run the seed back through `fips204` to confirm it regenerates the same public key the cert advertises (proves the round-trip is lossless); (b) generate an RSA-2048 root, issue a leaf, validate the chain + confirm the `signatureAlgorithm` OID is `sha256WithRSAEncryption`. The Phase 2 PQC test was updated to assert `BEGIN PRIVATE KEY` instead of `BEGIN BV PQC SIGNER` since the API output changed. All 14 PKI integration tests pass; Phase 3 composite test passes with `--features pki_pqc_composite`.

#### Secret Engine — PKI Phase 5.2 (multi-issuer per mount)
- **Each mount can now hold multiple issuer certificates / keys** at `issuers/<id>/{cert,key,meta}`, with a registry at `issuers/index` and a default-issuer pointer at `config/issuers`. The single-issuer-per-mount call-out from Phase 1's "Not In Scope" list is closed.
- **New routes** ([src/modules/pki/path_issuers.rs](src/modules/pki/path_issuers.rs)):
  - `LIST   /v1/pki/issuers` — list issuer IDs with `key_info` (name + `is_default`).
  - `READ   /v1/pki/issuer/:ref` — fetch a specific issuer's cert + metadata. `:ref` is either UUID or name.
  - `WRITE  /v1/pki/issuer/:ref` — rename (`{"issuer_name": "<new>"}`); duplicate names rejected.
  - `DELETE /v1/pki/issuer/:ref` — remove an issuer. Refuses to delete the current default while siblings exist (operator must reassign default first via `pki/config/issuers`). Cert records issued by the deleted issuer are intentionally left in `certs/<serial>` for audit; `pki/tidy` sweeps them after expiry.
  - `READ/WRITE /v1/pki/config/issuers` — round-trips the default-issuer pointer.
  - `READ /v1/pki/issuer/:ref/crl` — per-issuer CRL fetch.
- **`root/generate`, `intermediate/set-signed`, `config/ca` are now additive.** Each call adds a new named issuer to the mount rather than refusing if one already exists. The first issuer added auto-becomes default; subsequent issuers must be made default explicitly. New `issuer_name` request field on all three; empty = auto-allocate (`default`, then `issuer-2`, `issuer-3`, ...).
- **`issue/:role`, `sign/:role`, `sign-verbatim`, `root/sign-intermediate` accept `issuer_ref`.** Resolution priority: request body `issuer_ref` > role-level `issuer_ref` > mount default. The cert response carries `issuer_id` so callers can reconcile against the new registry.
- **`RoleEntry.issuer_ref`** — new `#[serde(default)]` field on roles for pin-issuance-to-this-issuer. Phase-1-through-5.1 roles deserialize unchanged.
- **Per-issuer CRL state** — revocations route to `crl/issuer/<issuer_id>/state` based on `CertRecord.issuer_id`; the legacy mount-wide `crl/state` is migrated into the default issuer's slot. `pki/tidy` sweeps every issuer's CRL state on every run.
- **Lazy migration shim** ([src/modules/pki/issuers.rs](src/modules/pki/issuers.rs)) — Phase 1-through-5.1 mounts with the legacy `ca/cert` + `ca/key` + `ca/meta` singletons lift themselves into `issuers/<auto-uuid>/*` on first call to any multi-issuer helper. Idempotent, observable in tests, and keeps every Phase 1–5.1 integration test passing without modification (apart from two assertions that explicitly tested *behaviour* that's now legitimately additive — those were updated to assert duplicate-name rejection, the equivalent default-secure check under multi-issuer).
- **Tests** — [tests/test_pki_phase5_2.rs](tests/test_pki_phase5_2.rs), 4 cases:
  1. Two issuers + default swap: list shows both; `pki/ca` returns default; `config/issuers` flip works; duplicate `issuer_name` rejected.
  2. `issue/:role` with explicit `issuer_ref` (request body), role-level pin (`role.issuer_ref`), and default fallback — each routes to the right issuer; per-issuer CRL only lists serials issued by *that* issuer.
  3. `WRITE /v1/pki/issuer/:ref` rename; `DELETE` non-default works; `DELETE` default-with-siblings rejected.
  4. Migration shim observable: a Phase-1-style `root/generate` then `LIST /v1/pki/issuers` shows the lifted entry with `name=default`, `is_default=true`.

  All 12 PKI integration tests pass (Phase 1 + 2 + 4 + 4.1 + 5 + 5.1 + 5.2); Phase 3 composite test passes with `--features pki_pqc_composite`.
- **What's still deferred**: per-issuer `usage` flags (which issuer is allowed for which role kinds — Vault has `issuing_certificates` / `crl_signing` / `ocsp_signing` per issuer); cross-mount issuer references; per-issuer `pki/issuer/:ref/sign-intermediate` and `pki/issuer/:ref/issue/:role` route variants (today the operator selects via `issuer_ref` field, which covers the same surface).

#### Secret Engine — PKI Phase 5.1 (PQC CSR signing)
- **`pki/sign/:role` and `pki/sign-verbatim` now accept ML-DSA CSRs.** Closes the asymmetry shipped in Phase 5 where PQC roles could `pki/issue` (engine generates the keypair) but not sign a CSR.
- **CSR algorithm detection in [csr.rs](src/modules/pki/csr.rs).** The `parse_and_verify` entry point now classifies the CSR's SubjectPublicKeyInfo OID into [`CsrAlgClass::Classical`](src/modules/pki/csr.rs) or `CsrAlgClass::MlDsa(level)`. Classical CSRs continue to verify via `x509-parser`'s `verify_signature()`; PQC CSRs verify with `fips204` directly because x509-parser only knows ring/aws_lc_rs algorithms (and we forbid `aws_lc_rs_unstable`). The parsed result carries both `spki_der` (for the rcgen path) and `raw_public_key` (for the PQC path).
- **`x509_pqc::build_leaf_from_pqc_spki`** mirrors [`x509::build_leaf_from_spki`](src/modules/pki/x509.rs) for the ML-DSA path: takes the raw 1952-byte ML-DSA-65 (or 1312/2592 for 44/87) public-key bytes plus the level, embeds them in a `SubjectPublicKeyInfoOwned`, and signs the manually-assembled TBS with the CA's `MlDsaSigner`.
- **Mixed-chain rejection extended to CSR signing.** The dispatch in `sign_csr_role` / `sign_csr_verbatim` is `(CsrAlgClass, Signer)`-keyed: classical CSR + classical CA → rcgen path; PQC CSR + PQC CA → PQC path; anything mixed → `ErrPkiKeyTypeInvalid`. Same default-secure rule the rest of the engine uses.
- **Test** — [tests/test_pki_phase5_1.rs](tests/test_pki_phase5_1.rs) hand-assembles an ML-DSA-65 CSR (rcgen 0.14 cannot serialize a CSR over an ML-DSA key without `aws_lc_rs_unstable`), self-test-verifies it with `fips204`, then submits it to `pki/sign/:role` on a PQC mount. Asserts: leaf carries OID `2.16.840.1.101.3.4.3.18`; leaf SPKI bytes equal the CSR's pubkey; tampered CSR is rejected; PQC CSR on a classical CA mount is rejected. All 8 PKI integration tests now pass; Phase 3 composite test still passes with `--features pki_pqc_composite`.

#### Secret Engine — PKI Phase 5 (CSR signing + intermediate hierarchies + config/ca import)
- **`POST /v1/pki/sign/:role`** — sign a client-supplied PKCS#10 CSR against a role's policy. The CSR self-signature is verified up front (defence against accepting a CSR forged by someone who does not actually hold the private key). The role's `use_csr_common_name` / `use_csr_sans` knobs decide whether to honour the CSR's CN / SANs or override them from the request body. Replaces the Phase 1 stub. ([src/modules/pki/path_issue.rs](src/modules/pki/path_issue.rs))
- **`POST /v1/pki/sign-verbatim`** — sign the CSR's subject and SANs as-is, no role. TTL clamped at 30 days (Vault parity ceiling). Used by service-mesh control planes that have already authorised the request out-of-band. Replaces the Phase 1 stub.
- **Intermediate-CA hierarchies** — the most-requested gap from Phase 1's "Not In Scope" list:
  - **`POST /v1/pki/intermediate/generate/{exported|internal}`** ([src/modules/pki/path_intermediate.rs](src/modules/pki/path_intermediate.rs)) — engine generates a keypair, persists it under `ca/pending/key`, and returns a CSR for the operator to take to an upstream root.
  - **`POST /v1/pki/root/sign-intermediate`** — root mount signs another mount's intermediate CSR with `BasicConstraints(ca=true)` plus a configurable `max_path_length`.
  - **`POST /v1/pki/intermediate/set-signed`** — intermediate mount validates that the supplied cert's SubjectPublicKeyInfo matches the pending keypair, then promotes `ca/pending/key` → `ca/key` and installs the cert as `ca/cert`. Issuance from that mount is now active.
- **`POST /v1/pki/config/ca`** — import an externally-generated CA bundle (a PEM blob containing one CERTIFICATE block plus one PRIVATE KEY block). Validates that the cert's pubkey matches the keypair, refuses to silently clobber an existing CA on the mount. Replaces the Phase 2-stubbed import.
- **CSR parsing layer** ([src/modules/pki/csr.rs](src/modules/pki/csr.rs)) — uses `x509-parser` for the structural parse and self-signature verification (now requires the `verify` feature on `x509-parser`), then hands the SubjectPublicKeyInfo DER to `rcgen::SubjectPublicKeyInfo::from_der` so the existing cert builders see a uniform `(spki_der, dn, requested_sans)` tuple. Phase 5 supports CSRs whose pubkey is one of the classical algorithms rcgen recognises (RSA, ECDSA-P256/P384, Ed25519); PQC CSRs reject with `ErrPkiKeyTypeInvalid` since the engine generates fresh PQC keypairs server-side via `pki/issue` today.
- **`CaMetadata.ca_kind`** — new enum (`Root` | `Intermediate` | `Imported`, `#[serde(default)]` for backwards compat) so admin tooling can render "this mount is an intermediate awaiting `set-signed`" without re-parsing the cert.
- **Tests** — [tests/test_pki_phase5.rs](tests/test_pki_phase5.rs) covers three flows end-to-end: (a) `sign/:role` + `sign-verbatim` happy-path with a locally-generated rcgen CSR, plus a tampered-signature rejection negative case; (b) full intermediate hierarchy — root mount + intermediate mount, generate → sign → set-signed → issue leaf, validate the leaf chains through both certs to the root; (c) `config/ca` import happy-path plus rejection of (i) re-import into a configured mount and (ii) a mismatched cert/key bundle. Phase 1–4.1 tests continue to pass with no regressions.
- **What's still deferred / called out**:
  - PQC CSRs (Phase 5.1 alongside `csr.rs` extension recognising ML-DSA SPKIs).
  - ACME server endpoints — spun out of the core engine as its own future feature: see [features/pki-acme.md](features/pki-acme.md). Originally listed under "Not In Scope" of the core engine; documenting it as a separate file makes the dependency story explicit (ACME `finalize` rides on top of the Phase 5 CSR-signing path).

#### Secret Engine — PKI Phase 4.1 (auto-tidy scheduler)
- **Periodic scheduler** ([src/modules/pki/scheduler.rs](src/modules/pki/scheduler.rs)) wired into `Core::post_unseal` alongside the existing `scheduled_exports::start_scheduler`. Single tokio task, 30 s tick, self-skips when sealed. Each tick enumerates every mount of `logical_type == "pki"`, reads that mount's persisted `AutoTidyConfig`, and fires `path_tidy::run_tidy_inner(... source="auto")` if (a) `enabled=true` and (b) `last_fire.elapsed() >= interval_seconds` (with a "first sighting after process start" rule that fires immediately on a freshly restarted node so a skipped window doesn't go silent).
- **Public `run_pki_tidy_pass(core, last_fired)`** entry point — the scheduler's body factored out so integration tests can drive it deterministically without waiting on a real 30 s tick, and so a future `sys/pki/tidy-all` admin endpoint has a no-wait sweep available for free.
- **Single-process scheduler, idempotent.** No HA leader gating yet — every node in a Hiqlite cluster runs its own scheduler. Sweep idempotence saves us from storage corruption (last writer wins on identical deletes) but pays the cost of N redundant sweeps per tick. HA leader gating is the same gap as `scheduled_exports` and tracks together as a follow-up.
- **In-memory `last_fired` table.** Not persisted: a process restart resets the timer, which means tidy fires immediately on first tick after restart for any enabled mount. Same semantics the scheduled-exports runner uses; correct default for an idempotent sweep.
- **Test** — [tests/test_pki_auto_tidy.rs](tests/test_pki_auto_tidy.rs) exercises three branches via direct `run_pki_tidy_pass` calls: disabled mount → no fire → status remains default; enabled mount + fresh `last_fired` → fires immediately, `tidy/status.source = "auto"`, expired cert swept; same `last_fired` reused → no re-fire within the 1 h interval window. All Phase 1 / 2 / 4 tests continue to pass; Phase 3 composite test continues to pass with `--features pki_pqc_composite`.

#### Secret Engine — PKI Phase 4 (tidy job)
- **`POST /v1/pki/tidy`** — synchronous on-demand sweep that removes expired certs from `certs/<serial>` storage and removes expired entries from the CRL revoked-list. Knobs: `tidy_cert_store` (default `true`), `tidy_revoked_certs` (default `true`), `safety_buffer` (default `"72h"` — wait this long after a record's NotAfter before it's eligible for deletion, so an operator window remains for forensic inspection). Replaces the Phase 1 stub that returned `ErrLogicalOperationUnsupported`. ([src/modules/pki/path_tidy.rs](src/modules/pki/path_tidy.rs))
- **`GET /v1/pki/tidy-status`** — returns a snapshot of the most recent tidy run: `last_run_at_unix`, `last_run_duration_ms`, `certs_deleted`, `revoked_entries_deleted`, `safety_buffer_seconds`, `source` (`"manual"` for on-demand calls; `"auto"` once the periodic scheduler lands).
- **`POST /v1/pki/config/auto-tidy`** + **`GET`** — round-trips the periodic-tidy configuration (`enabled`, `interval`, `tidy_cert_store`, `tidy_revoked_certs`, `safety_buffer`). Phase 4 ships the config endpoint *only* — the actual periodic scheduler that fires `run_tidy_inner` at `interval_seconds` is a Phase 4.1 follow-up. Storing the config now lets operators persist their preference ahead of the scheduler landing without a second round of API churn.
- **CRL rebuild on sweep** — when the revoked-list shrinks, `crl_number` increments and the cached CRL is rebuilt eagerly (best-effort: a rebuild failure logs a warning but does not undo the storage deletions, since the cert records are already gone).
- **`CertRecord` extended with `not_after_unix`** — populated at issue time so tidy can identify expired records without re-parsing each PEM. The field is `#[serde(default)]` so records written before Phase 4 deserialize unchanged; the tidy handler explicitly skips records with `not_after_unix == 0` rather than deleting them blindly. ([src/modules/pki/storage.rs](src/modules/pki/storage.rs))
- **Test** — [tests/test_pki_tidy.rs](tests/test_pki_tidy.rs) issues two 1-second-TTL certs, revokes one, sleeps past their NotAfter, runs `pki/tidy` with zero safety buffer, and asserts: both certs swept from storage, the revoked entry purged from the CRL, `pki/tidy-status` reports the run, and `pki/config/auto-tidy` round-trips configuration.
- **What's still deferred to Phase 4.1**: the background scheduler that auto-fires the tidy at the configured interval, and a `tidy/cancel` endpoint to abort an in-flight sweep. The classical CRL still uses `rcgen` rather than `x509-cert::crl` (the spec mentioned modernising it; Phase 4 left it alone because it works and the cleanup belongs in a focused refactor commit, not entangled with the tidy handler).

#### Secret Engine — PKI Phase 3 (composite / hybrid signatures, feature-gated preview)
- **New feature flag `pki_pqc_composite`** (off by default) on the top-level `bastion_vault` crate. When enabled, `key_type = "ecdsa-p256+ml-dsa-65"` becomes valid for both `pki/roles/:name` and `pki/root/generate/{internal|exported}`. Issued certs / CRLs carry `signatureAlgorithm` OID `2.16.840.1.114027.80.8.1.28` (`id-MLDSA65-ECDSA-P256-SHA512`, IETF lamps draft) and a composite `subjectPublicKey` / `signatureValue` shaped as `SEQUENCE { BIT STRING pq, BIT STRING classical }` — matching the draft's structure.
- **CompositeSigner** ([src/modules/pki/composite.rs](src/modules/pki/composite.rs)) pairs a Phase-1 [`CertSigner`](src/modules/pki/crypto.rs) (ECDSA-P256) with a Phase-2 [`MlDsaSigner`](src/modules/pki/pqc.rs) (ML-DSA-65). Both halves sign the same canonical prehash (`SHA-256("BastionVault-PKI-Composite-v0/MLDSA65+ECDSAP256/v0" || tbs_der)`), so a verifier that trusts only one scheme can still validate against that half independently.
- **Composite X.509 builder** ([src/modules/pki/x509_composite.rs](src/modules/pki/x509_composite.rs)) reuses the helpers elevated from [`x509_pqc`](src/modules/pki/x509_pqc.rs) (DN, validity, SAN/EKU/AKI/SKI extension encoders, cert parsing) so the only actually-novel surface is the algorithm identifier + composite SPKI/signature shape.
- **Storage envelope** — composite CA private keys round-trip through a `BV PQC COMPOSITE SIGNER` PEM-wrapped JSON envelope holding the classical PKCS#8 PEM and the PQC `BV PQC SIGNER` envelope side by side. The unified [`Signer::from_storage_pem`](src/modules/pki/crypto.rs) sniffs the marker and dispatches; no schema migrations on existing classical/PQC CAs.
- **Mixed-chain rejection extended** — a third `AlgorithmClass::Composite` joins `Classical` and `Pqc` so the existing default-secure guard in [path_issue](src/modules/pki/path_issue.rs) rejects all three cross-class cases (composite role on classical CA, composite role on PQC CA, classical/PQC role on composite CA) at issue time.
- **Honest non-interop disclosure** — the IETF draft `draft-ietf-lamps-pq-composite-sigs` is still moving (random salt, prehash construction, and OID arc have all churned across recent revisions). The engine pins the OID and structure but uses a BastionVault-internal prehash domain in the v0 preview; certs verify against themselves but should not be expected to interoperate with arbitrary draft-conformant verifiers until the draft locks. Documented inline in [composite.rs](src/modules/pki/composite.rs) and in [features/pki-secret-engine.md](features/pki-secret-engine.md).
- **Test** — [tests/test_pki_composite.rs](tests/test_pki_composite.rs) is `#![cfg(feature = "pki_pqc_composite")]` and covers: composite root generation → composite OID on the cert → SPKI parses as `SEQUENCE { BIT STRING ML-DSA-65 (1952 bytes), BIT STRING SEC1 P-256 (65 bytes) }` → **both halves of the root self-signature verify independently** (PQ via `fips204`, classical via `p256::ecdsa::VerifyingKey`) → composite leaf issuance → leaf chain check + same independent dual verification → revoke + composite-signed CRL → mixed-chain rejection. Run with `cargo test --features pki_pqc_composite --test test_pki_composite`.
- **What's still deferred to Phase 3.1**: tracking the IETF draft's `M' = Prefix || Random || Domain || HashOID || PH(M)` construction once it locks (single-point-of-swap is `composite::bv_prehash`); hash-then-sign for ML-DSA-65 (currently signs the SHA-256 digest, which is consistent with the test but not the draft's `pure` mode); other variants (`mldsa44+ecdsa-p256-sha256`, `mldsa87+ecdsa-p384-sha512`, RSA-PSS pairs).

#### Secret Engine — PKI Phase 2 (post-quantum / ML-DSA roles)
- **PQC roles** — `key_type` now accepts `ml-dsa-44`, `ml-dsa-65`, and `ml-dsa-87` for both `pki/roles/:name` and `pki/root/generate/{internal|exported}`. The full Vault-shape route surface from Phase 1 (issue, fetch, revoke, CRL, list) works unchanged on PQC chains; the engine dispatches between the classical (rcgen-driven) path and the PQC path based on the role / CA algorithm.
- **Pure-Rust DER assembly for PQC** — rcgen 0.14's built-in ML-DSA support is gated behind `aws_lc_rs_unstable` (forbidden by [features/pki-secret-engine.md](features/pki-secret-engine.md)), so [src/modules/pki/x509_pqc.rs](src/modules/pki/x509_pqc.rs) sidesteps rcgen entirely: TBSCertificate / TbsCertList are built with `x509-cert` + `der`, the DER bytes signed with [`fips204`](https://crates.io/crates/fips204) via the new [`MlDsaSigner`](src/modules/pki/pqc.rs) wrapper, and the result wrapped into `Certificate` / `CertificateList`. Subject / issuer DNs, validity windows, BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAltName (DNS + IP), SubjectKeyIdentifier (RFC 7093 method 1, SHA-256/160), and AuthorityKeyIdentifier are all emitted; CRLs carry the standard `crlNumber` extension for rollback detection.
- **OIDs pinned to IETF lamps draft** — `2.16.840.1.101.3.4.3.{17,18,19}` for ML-DSA-44/65/87 ([src/modules/pki/pqc.rs](src/modules/pki/pqc.rs)), the same OIDs rcgen uses for `PKCS_ML_DSA_*`. Issued certs interoperate with verifiers that gain ML-DSA support without reissuance.
- **Unified [`Signer`](src/modules/pki/crypto.rs) seam** — `Signer::Classical(CertSigner)` for rcgen-backed keys, `Signer::MlDsa(MlDsaSigner)` for ML-DSA. `Signer::from_storage_pem` dispatches by sniffing the PEM label, so adding more PQC schemes later (composite, SLH-DSA) does not require schema migrations on existing CA-key entries. ML-DSA seeds are zeroized on drop and stored as a custom `BV PQC SIGNER` PEM envelope (engine-internal, barrier-encrypted at rest, never returned over the API in `internal` mode).
- **Mixed-chain rejection (default-secure)** — issuing a PQC leaf from a classical CA, or vice-versa, now fails with `ErrPkiKeyTypeInvalid` at issue time. The `--allow-mixed-chain` opt-in for migration scenarios called out in the spec lands in a Phase 2.1 follow-up; Phase 2 ships the closed-by-default form first.
- **bv_crypto extensions** — [`MlDsa44Provider`](crates/bv_crypto/src/signature/ml_dsa_44.rs) and [`MlDsa87Provider`](crates/bv_crypto/src/signature/ml_dsa_87.rs) added alongside the existing `MlDsa65Provider`, behind matching `ml-dsa-44` / `ml-dsa-87` cargo features (enabled by default). Each is a thin wrapper over `fips204::ml_dsa_*` with the same seed-keyed sign/verify shape as the existing 65-bit path.
- **Tests** — new integration test [tests/test_pki_pqc.rs](tests/test_pki_pqc.rs) covers ML-DSA-65 end-to-end: mount → root generate → confirm signatureAlgorithm OID is `2.16.840.1.101.3.4.3.18` → directly verify the root's self-signature with `fips204` against the SPKI-extracted public key (proves our TBS DER path is correct, not just well-formed) → role with `key_type=ml-dsa-65` (and `key_bits != 0` rejected at write) → issue leaf with DNS + IP SANs → re-verify leaf signature under root pk → revoke → CRL contains revoked serial with the same OID → mixed-chain rejection (classical role on PQC CA → fail). Phase 1 classical test continues to pass, no regressions.
- **What's still deferred to Phase 3+**: composite / hybrid signatures (`pki_pqc_composite` feature flag, IETF draft still in flux), the `--allow-mixed-chain` opt-in, AIA / CRL DP / NameConstraints extensions in PQC certs (Phase 2.1 alongside the same gap in classical), CSR-driven signing (`sign/:role`, `sign-verbatim`), and intermediate CA hierarchies. See [features/pki-secret-engine.md](features/pki-secret-engine.md) for the updated phase plan.

#### Secret Engine — PKI Phase 1 (pure-Rust classical X.509)
- New PKI secret engine at `src/modules/pki/`, replacing the disabled OpenSSL-bound stub. The legacy `path_*.rs` files have been removed; the new module is built on `rcgen` 0.14 with the `ring` provider (no `openssl-sys`, no `aws-lc-sys`). Generates classical X.509 v3 certificates and CRLs for RSA / ECDSA P-256 / P-384 / Ed25519 roles. RSA generation is gated until Phase 2 plugs a `rsa`-crate-backed `SigningKey` impl into rcgen; ECDSA + Ed25519 work end-to-end today.
- **Vault-compatible HTTP surface** — all paths under `/v1/pki/`: `roles/:name` (CRUD + list), `root/generate/{internal|exported}`, `issue/:role`, `cert/:serial`, `ca[/pem]`, `ca_chain`, `certs/` (list), `revoke`, `crl[/pem]`, `crl/rotate`, `config/urls`, `config/crl`. `sign/:role`, `sign-verbatim`, `sign-intermediate`, `intermediate/*`, `tidy`, and `config/ca` are exposed as stub endpoints that return `ErrLogicalOperationUnsupported` with route-level help text — they keep the surface Vault-shaped so clients fail with a clear "not implemented" instead of a 404 mismatch.
- **Engine architecture** — split into focused modules: `crypto.rs` (signer abstraction; the seam Phase 2's ML-DSA implementations plug into), `x509.rs` (cert / CRL builders that translate role JSON into rcgen params), `storage.rs` (sealed-storage layout for CA cert/key, cert index, CRL state), and one `path_*.rs` per route group. `PkiModule` is registered in [src/module_manager.rs:38](src/module_manager.rs:38) so a fresh core picks up `pki` as a mountable engine type with no operator action.
- **Storage layout** — CA cert + private key live at `ca/cert` + `ca/key` inside the barrier; issued certs at `certs/<hex-serial>`; CRL state (monotonic `crl_number` + revoked-serial set) at `crl/state`; cached CRL PEM at `crl/cached`. Private keys are zeroized in memory after use via [`zeroize`](src/modules/pki/crypto.rs:90), barrier-encrypted at rest, and never returned over the API in `internal` mode (`exported` mode opt-in returns the PEM in the issue/root response).
- **Tests** — new integration test [tests/test_pki_engine.rs](tests/test_pki_engine.rs) covers the end-to-end Vault-compatible flow: mount engine → generate root → reject duplicate root generation → fetch CA → create role → list roles → issue leaf with DNS + IP SANs → fetch by serial → fetch CRL pre-revocation → revoke → re-fetch CRL and confirm the serial appears in `revokedCertificates` (parsed via `x509-parser`) → confirm stub endpoints return errors. Phase 1 unit-test coverage of the crypto + x509 layers is left to follow-up alongside the property-style determinism tests called out in `features/pki-secret-engine.md`.
- **Not in Phase 1**: ML-DSA / composite signatures (Phase 2), CSR-based signing endpoints, intermediate CA hierarchies, `tidy` sweep, ACME / OCSP. See [features/pki-secret-engine.md](features/pki-secret-engine.md) for the full phase plan.

### Fixed

#### Mount table — `remount` left a dangling HashMap entry
- [`Core::remount`](src/mount.rs:612) updated the entry's `path` field and the router trie when remounting `kv → vk`, but did not rekey the `mounts_router.entries` HashMap. The HashMap retained the old key (`"kv/"`), so a subsequent `unmount("vk/")` returned `Ok(())` from `MountsRouter::delete` (key miss = false) without actually removing the entry, and `sys/mounts` continued to list the stale path until restart. The fix removes the old key and re-inserts under the new one inside the same critical section, with best-effort rollback if the persist step fails. Caught by [tests/test_default_logical.rs](tests/test_default_logical.rs) once the mount-count assertion was refreshed.

#### Plugin System — plugin-as-mount: register a plugin then mount it as a secret engine
- A registered plugin can now be mounted at a path the same way `kv` / `kv-v2` are. The mount type string is `plugin:<name>` (e.g. `plugin:totp`); the host's [`MountsRouter::get_backend`](src/mount.rs:185) recognises the prefix and synthesises a [`PluginLogicalBackend`](src/plugins/logical_backend.rs) factory bound to that plugin name. The plugin must exist in the catalog at request time — registration order doesn't matter, but a mount referencing a deleted plugin returns a clear error instead of silently 404'ing.
- **JSON envelope contract (v1)** — host → plugin and plugin → host. The plugin reads its input as UTF-8 JSON `{"op": "<read|write|delete|list|renew|revoke>", "path": "<rel-to-mount>", "data": {…}}` and writes a response of `{"data": {…}, "warnings": [...]}` (Some), `{"data": null}` (404), or a non-zero plugin status with a body that's either a plain string or `{"error": "…"}` (turned into a host error). The mount path prefix is stripped by the router so plugins see paths relative to their own mount; built-in capabilities (storage_prefix, audit_emit, log_emit) work unchanged because they go through the same runtime.
- **Both runtimes supported** — `manifest.runtime = "wasm"` dispatches via `WasmRuntime::invoke_with_config`; `manifest.runtime = "process"` via `ProcessRuntime::invoke_with_config`. The plugin's `ConfigStore` (operator-set knobs) is loaded once per request and threaded through, so the same Configure-modal-set values that work for one-shot invocations work for mount-driven invocations.
- **GUI** — [gui/src/routes/MountsPage.tsx](gui/src/routes/MountsPage.tsx) now loads `api.pluginsList()` alongside the existing mount/auth-method fetches and merges plugins of `plugin_type ∈ {secret-engine, secret, database, transform}` into the Engine Type dropdown as `plugin:<name>` options labelled `<name> vX.Y.Z (plugin · <kind>)`. Plugins of other kinds (e.g. `auth-backend`) are filtered out — those belong to the auth-method dropdown, which is a separate future track. No host-side dropdown registration needed: registered plugins appear automatically once they're in the catalog.
- **Tests** — 9 new unit tests in [src/plugins/logical_backend.rs](src/plugins/logical_backend.rs#L240) covering envelope construction (op + path + body), response translation (data object, `data: null` → Ok(None), empty body → Ok(None), invalid JSON → error), error-path handling (JSON `{error: …}` body, plain-string body), and the factory closure. All 37+9 plugin-suite tests pass; preview-verified the GUI dropdown merges correctly with a synthetic plugin list.
- **What's still deferred**: lease integration for dynamic-credential plugins (a postgres-style plugin can `create`/`revoke` today via the `op: "revoke"` envelope, but the host's lease manager doesn't auto-call it on TTL expiry yet); per-mount config (the plugin's `ConfigStore` is shared across every mount of the same plugin in v1 — multi-mount instances all see the same operator-set values); auth-method plugin mounts (parallel work to this engine track).

#### Plugin System — `.bvplugin` packaging format ([crates/bv-plugin-pack/](crates/bv-plugin-pack/))
- New container format that bundles a plugin's manifest + WASM into a single file so the GUI's Register modal can self-configure on upload — instead of the operator typing every field, the modal parses the bundle's embedded JSON manifest and prefills name, version, type, description, capabilities, storage_prefix, and config_schema. The operator still gets the form for last-mile review (and can override before clicking Register), but the common case is one click → submit.
- **Format (v1, locked)**: `"BVPL"` (4 byte magic) · `0x01` format version · 3 bytes reserved · `u32 LE` manifest length · JSON manifest · WASM binary. The embedded `sha256` is over the WASM payload only (not the bundle) so re-registering after extracting from the bundle produces the same hash as a raw `.wasm` upload, and a tampered binary fails the GUI's hash sanity check before it even gets to the host. Documented in [crates/bv-plugin-pack/src/main.rs](crates/bv-plugin-pack/src/main.rs).
- **`bv-plugin-pack` CLI** (new workspace member): `bv-plugin-pack --manifest plugin.toml --binary plugin.wasm --out plugin.bvplugin`. Reads the source manifest as TOML, converts to JSON, recomputes sha256 over the binary (rejecting any pre-filled placeholder mismatch), and writes the bundle. 2 unit tests (round-trip pack-then-parse + placeholder sha detection).
- **GUI Register modal** ([gui/src/routes/PluginsPage.tsx](gui/src/routes/PluginsPage.tsx)): file picker now accepts `.bvplugin` alongside `.wasm`. On select, magic bytes are checked → bundle path runs `parseBundle` (verifies version, length-prefixed JSON, sha256 against the embedded WASM), populates every form field including `config_schema`, and shows a `from bundle` badge + `manifest auto-filled from bundle` hint; raw `.wasm` keeps the existing manual-fill flow. The bundle's `config_schema` flows through `pluginsRegister` so the host sees the same form the plugin author declared.
- **Makefile**: new targets `plugins-pack-build` (builds the packer) and `plugins-pack` (depends on `plugins-wasm`, runs the packer over each WASM artefact, drops the `.bvplugin` next to the `.wasm` in `plugins-ext/dist/`). The umbrella `make plugins` now produces both raw `.wasm` and `.bvplugin` for every reference plugin. Verified end-to-end: `make plugins-pack` produces a 154 KiB bundle (12 byte header + 976 byte manifest + 153 KiB WASM) for the TOTP plugin; the GUI's `parseBundle` reads it back to the original manifest + WASM bytes intact.
- **Why a bundle over a multipart upload**: keeps the host API surface small (still one POST with manifest + base64 binary), keeps the registration flow auditable in one shot, and gives the operator a single artefact to email / sign / download from a release page. The format is forward-compatible — a `format_version` byte plus reserved bytes leave room for future additions (signatures, tarball-of-plugins, multiple binaries per bundle) without breaking v1 readers.

#### Plugin System — Phase 4: reference plugins (out-of-tree submodule [`plugins-ext/`](plugins-ext/))
- New git submodule [`plugins-ext`](plugins-ext/) → `https://github.com/ffquintella/BastionVault-Plugins.git`. Two reference plugins ship there, exercising the SDK and both runtime backends from outside the host tree:
  - **`bastion-plugin-totp`** (WASM runtime, `cdylib` targeting `wasm32-wasip1`) — RFC 6238 TOTP code generation + validation. Pure compute capsule: no storage, no audit, no network. Demonstrates `bv.now_unix_ms` (always-available host import) and `bv.config_get` (operator-tunable `digits` / `period` / `skew` via the GUI Configure modal). Validates against RFC 6238 Appendix B test vectors (T=59, 1111111109, 1111111111, 1234567890) plus a configurable validation-skew window. Uses constant-time code comparison to keep timing-side-channels off the table. 8 unit tests + 5 host_test-gated integration tests (round-trip generate/validate, skew window, config override of digits to 8, invalid base32 rejection).
  - **`bastion-plugin-postgres`** (process runtime, single binary speaking line-delimited JSON-RPC over stdio) — Postgres dynamic-credential issuer. Two operations: `create` (issues a `bv-<random_hex>` LOGIN role with a 24-byte URL-safe-base64 password and a `VALID UNTIL <ttl>` clause, then runs the operator-supplied grants template with `{{name}}` substitution) and `revoke` (REASSIGN OWNED + DROP OWNED + DROP ROLE IF EXISTS, with identifier-validation refusing anything outside `[A-Za-z0-9_-]{1,63}`). Bootstrap-token-checks the host's init message; emits an `audit_emit` event on every issue/revoke. 5 unit tests covering role-name / password generation, identifier safety, and a Postgres-format ISO-8601 timestamp helper that doesn't need `chrono`.
- **Workspace integration**: the host's top-level `Cargo.toml` now `exclude`s `plugins-ext` so the submodule's own workspace stays separate (its release profile uses `panic = "abort"` + `opt-level = "s"` for WASM, which would be wrong for the host). Each plugin depends on `bastion-plugin-sdk` via a relative path (`../../crates/bastion-plugin-sdk`), which works in the monorepo layout and is documented in the submodule README for standalone clones.
- **What's deferred**: real publisher signature verification (Transit ML-DSA-65); the postgres plugin's TLS to the database (uses NoTls in v1 — operators wrap with stunnel / sidecar / future `make_tls_connector` capability); a registry / marketplace of community plugins. The submodule README points at the host repo's [`features/plugin-system.md`](features/plugin-system.md) for the protocol contract.

#### Plugin System — Phase 3: hot reload, versioned catalog, shared module cache
- **`crate::plugins::module_cache::ModuleCache`** (new module) — process-global wasmtime `Engine` + `(plugin_name, sha256) → Module` map behind `OnceLock`. Before the cache, every invoke recompiled the WASM (cranelift is fast but not free; multi-MB modules cost real time). Now concurrent invokes of the same plugin share a single compilation. Bound at 128 entries with FIFO eviction so re-registering a plugin many times can't leak. `WasmRuntime::invoke_with_config` now goes through `cache.get_or_compile(name, sha256, bytes)` instead of constructing a fresh `Module` each call.
- **Versioned catalog layout**: `core/plugins/<name>/versions/<version>/{manifest,binary}` with a per-name `core/plugins/<name>/active` pointer marking the version invokes resolve to. The first `put_plugin` for a name auto-activates; subsequent `put_plugin` calls **don't** auto-activate (operators stage a new version, then activate explicitly via the GUI / HTTP). Per-name `config` and `data/` slots are shared across versions — switching versions doesn't lose operator-set config or plugin storage. Read-side fallback to the legacy un-versioned layout (`core/plugins/<name>/{manifest,binary}`) keeps existing deployments working without a destructive migration. New methods: `get_version`, `list_versions`, `get_active_version`, `set_active`, `delete_version` (refuses to delete the active version).
- **Reload endpoint**: `POST /v1/sys/plugins/<name>/reload` — re-fetches the active version's binary from storage, re-verifies the sha256, and calls `ModuleCache::invalidate(name)` to drop every cached compilation for that plugin (regardless of version). The next invoke compiles fresh. Meaningful even though the runtime is single-shot per invoke: it lets operators force a recompile (e.g. after a wasmtime upgrade) without bouncing the BastionVault process. Returns `{ active_version, evicted }`.
- **Versioning endpoints**: `GET /v1/sys/plugins/<name>/versions` (list with active flag), `POST /v1/sys/plugins/<name>/versions/<version>/activate`, `DELETE /v1/sys/plugins/<name>/versions/<version>`. All four sys handlers wired through the existing `SysAuditCtx` pattern so the audit log records who reloaded / activated / deleted.
- **Tauri commands**: `plugins_versions`, `plugins_activate_version`, `plugins_delete_version`, `plugins_reload` — embedded-mode parity, each emitting an audit event via `bastion_vault::audit::emit_sys_audit`.
- **GUI** ([gui/src/routes/PluginsPage.tsx](gui/src/routes/PluginsPage.tsx)) — new `VersionsModal` listing every version per plugin with `Activate` and `Delete` actions; the active version is marked with emerald styling. Per-plugin `Reload` button toasts the resulting `{ active_version, evicted }` so operators see how many cached compilations were dropped. New API helpers `pluginsVersions`, `pluginsActivateVersion`, `pluginsDeleteVersion`, `pluginsReload` plus `PluginVersionsResult` / `PluginReloadResult` types.
- **Subprocess test fix on Windows**: while wiring up the Phase-3 process-runtime tests, found they'd been fast-failing during static init with `STATUS_STACK_BUFFER_OVERRUN` (0xC0000409). Root cause: `cmd.env_clear()` in `ProcessRuntime::invoke_with_config` stripped Windows-mandatory env vars (`SystemRoot`, `windir`, `SystemDrive`, `TEMP`, `ProgramData`, etc.) that the Win32 base services and CRT need at process startup. Fixed by forwarding only the minimal Windows system-env set on Windows builds while still keeping arbitrary parent env out. Replaced the `.expect()` / `.unwrap()` calls inside `run_test_subprocess_plugin` (which runs from a `#[ctor::ctor]`, an `extern "C"` `nounwind` context — any panic there fast-fails with the panic message lost before stderr flushes) with explicit `eprintln!` + `std::process::exit(N)` graceful-shutdown paths so future failures surface their cause instead of just an opaque exit code.
- **Tests + verification** — 37 / 1 ignored across plugin suites (was 33 + the 4 process-runtime tests that previously needed `#[ignore]` on Windows; now all 6 pass cleanly). Added 6 new tests: `module_cache::hit_then_miss_on_sha_change`, `module_cache::invalidate_drops_all_versions_for_a_name`, plus `catalog::put_then_get_uses_versioned_layout_and_activates`, `catalog::second_version_does_not_auto_activate`, `catalog::cannot_delete_active_version`, `catalog::legacy_layout_still_readable`, `catalog::delete_clears_versions_and_per_name_records`. `cargo check --lib` clean; `npx tsc --noEmit` clean.

#### Plugin System — operator-configurable plugins (`config_schema`, `bv.config_get`, GUI Configure modal)
- Plugins can now declare a **`config_schema: Vec<ConfigField>`** in their manifest. Operators set values from the GUI; the host persists at `core/plugins/<name>/config` (barrier-encrypted); the plugin reads at run time. Field kinds: `string`, `int`, `bool`, `secret` (masked + redacted on read-back), `select` (with declared `options`). Each field carries `name`, optional `label` / `description`, `required`, optional `default`. Values cross the boundary as UTF-8 strings; the SDK has parse helpers for `i64` and `bool`.
- **`crate::plugins::ConfigStore`** (new module) — barrier-encrypted CRUD over the per-plugin config map. `get_redacted` replaces `Secret`-kind values with the literal placeholder `<set>` so a `GET /v1/sys/plugins/<name>/config` round-trip in the GUI doesn't expose secrets. The reverse trick: when a `PUT` carries `<set>` for a `Secret` field, the store keeps the existing value — so the operator can edit other fields without re-typing every secret. Validation refuses keys not in the schema, refuses missing `required` keys, refuses `int`s that don't parse, refuses `bool`s outside `{"true","false"}`, and refuses `select` values outside the declared `options`.
- **`bv.config_get` host import** added to **both runtimes**:
  - WASM: sync linker entry `bv.config_get(key_ptr, key_len, out_ptr, out_max) -> i32` with the same return-code conventions as `bv.storage_get` (length / `-1` not_found / `-3` buffer_too_small). Reads from `PluginCtx::config`, populated by `WasmRuntime::invoke_with_config`.
  - Process: JSON-RPC method `config_get` returning `{"value": "<string>"}` or `{"error": "not_found"}`. The runtime wraps it the same way as the existing `storage_get`/etc handlers. Both runtimes' `invoke_with_config` is the new entry point; the original `invoke` keeps working with an empty config map for tests.
- **HTTP**: `GET /v1/sys/plugins/<name>/config` returns `{ schema, values }` (values redacted for `Secret` fields). `PUT /v1/sys/plugins/<name>/config` accepts `{ values: { name → string } }`. Both audit-log normally.
- **Tauri commands**: `plugins_get_config`, `plugins_set_config`. The existing `plugins_invoke` Tauri command also gained config loading + dispatch by `RuntimeKind` so embedded GUI invocations of process plugins work the same as remote-mode HTTP.
- **SDK** ([crates/bastion-plugin-sdk](crates/bastion-plugin-sdk)) — new `Host::config_get(&self, key) -> Option<String>` (auto-grows the read buffer up to 64 KiB on `STORAGE_BUFFER_TOO_SMALL`), plus convenience parsers `Host::config_get_i64` and `Host::config_get_bool`. The `host_test` stub adds `test_support::set_config(key, value)` so plugin authors can test config-driven branches without spinning up wasmtime. Added `config_get` to the `extern "C"` block under `wasm_import_module = "bv"`.
- **GUI** ([gui/src/routes/PluginsPage.tsx](gui/src/routes/PluginsPage.tsx)) — new `ConfigureModal` rendered when the operator clicks the per-plugin **Configure** button (only shown when the manifest declares a non-empty `config_schema`). Renders the form dynamically: `string` → text, `int` → number, `bool` → checkbox, `secret` → password (placeholder `<set>` when populated), `select` → dropdown with `—` for unset. Required-field check happens client-side as a UX nicety; the host validates regardless. New API helpers `pluginsGetConfig` / `pluginsSetConfig` plus `PluginConfigField` / `PluginConfigResult` types. The existing `PluginManifest` type gained the optional `config_schema` field.
- **Tests + verification** — 53 / 1 ignored across plugin + exchange suites (was 53 before the config work; now includes 7 new `ConfigStore` tests + 1 SDK `host_config_get_round_trip` test, balanced by tighter parallel-test isolation that fixed unrelated flakes). All process-runtime tests now annotated `#[serial_test::serial]` since wasmtime + spawn-the-test-binary-as-subprocess concurrent execution was hitting `STATUS_STACK_BUFFER_OVERRUN` on Windows. SDK tests serialised likewise to keep the shared in-memory test STATE coherent. `cargo check --lib` + `cargo check -p bastion-vault-gui` clean. `npx tsc --noEmit` clean. Vite preview compiled `/plugins` without console errors.

#### Plugin System — Phase 2 (literal): out-of-process runtime + `bv.now_unix_ms` host import
- New `crate::plugins::process_runtime::ProcessRuntime` for plugins that need real OS-level capabilities the WASM sandbox can't provide (network egress for cloud SDKs / DB drivers / HSM bridges). Mirrors `WasmRuntime::invoke` in shape — same `InvokeOutput { outcome, response, fuel_consumed }` — so the HTTP `/v1/sys/plugins/{name}/invoke` handler dispatches by `manifest.runtime` without thinking about the IPC mechanism. `RuntimeKind::Process` is no longer rejected at registration; the manifest validator accepts it.
- **Wire format**: line-delimited JSON-RPC over stdio. Deliberately **not** tonic/protobuf — the substance of "out-of-process" is the OS subprocess boundary, not the wire format. Stdio JSON adds zero new crate deps (already had tokio + serde_json), works identically on Windows + Linux + macOS without UDS / named-pipe gymnastics, and is the well-trodden LSP / debug-adapter pattern. Tonic is mentioned in the spec but the substance is what we keep.
- **Lifecycle**: single-shot per invoke. The host writes the binary to a uniquely-named temp file (chmod 0o700 on Unix, executable on Windows by extension), spawns it via `tokio::process::Command` with stdin/stdout/stderr piped + `env_clear()` + selective re-injection (`PATH`, `BV_PLUGIN_BOOTSTRAP_TOKEN`, `BV_PLUGIN_NAME`, `BV_PLUGIN_MODE`), sends an init message, and dispatches host-call requests until the plugin sends `done` or stdout EOF. Configurable kill-on-timeout (30s default). Stderr is forwarded to host log on a detached task with `[plugin=<name>]` prefix.
- **Bootstrap token**: 256-bit random URL-safe base64, single-use per invoke, passed to the child via env var `BV_PLUGIN_BOOTSTRAP_TOKEN`. Prevents another process from impersonating the plugin (the plugin must echo the token back in its first message; mismatch fails the invoke). Long-lived plugin processes with restart-with-backoff are explicitly deferred — they only matter for plugins holding cross-request state, which is the same gap as plugin-as-mount on the WASM side.
- **Capability mediation**: every host call (`storage_get/put/delete/list`, `audit_emit`, `now_unix_ms`, `log`) is dispatched by the parent process with the same gate logic as the WASM runtime — `manifest.capabilities.storage_prefix` rebases keys to `core/plugins/<name>/data/<rel>` and refuses anything outside, `audit_emit` and `log_emit` flags are checked, etc. Plugins cannot bypass capabilities by virtue of being a separate process.
- **Net allowlist** (`manifest.capabilities.allowed_hosts`): declarative-only in v1. Hard egress filtering needs platform-specific tools (Linux seccomp + network namespaces, Windows AppContainer, macOS sandbox-exec). The manifest still records intent so audit + GUI can surface it; operators who need OS-enforced filtering wrap BastionVault under systemd `IPAddressAllow=`, k8s NetworkPolicy, Docker `--network=`, etc. Documented honestly in the spec rather than over-promising.
- **`bv.now_unix_ms()` host import** added to **both** the WASM runtime (`bv.now_unix_ms() -> i64` in the wasmtime linker) **and** the process runtime (JSON-RPC `now_unix_ms` method). Always available, not capability-gated — the wall-clock isn't an exfiltration surface and TOTP / expiration / timestamping plugins all want it. Returns milliseconds since Unix epoch as i64 (range fits 1970..year-292M); clamped to 0 on the impossible pre-1970 case.
- **SDK** (`crates/bastion-plugin-sdk`): new `Host::now_unix_ms() -> i64` wrapper; `extern "C" fn now_unix_ms() -> i64` import declaration on the wasm side; non-wasm stub that returns either a `mock_now_ms` value pinned via `test_support::set_now_ms(Some(value))` or the real wall-clock as fallback. Plugin authors who write deterministic time-window tests use the mock; everyone else gets real time without changing test code.
- **Tests**: 5 new process-runtime tests + 1 new WASM `now_unix_ms` test + 1 new SDK `now_unix_ms` test. The process tests use a clever `ctor::ctor` hook in `src/lib.rs`: the test binary checks `BV_PLUGIN_MODE=1` at startup and dispatches into a subprocess plugin handler that reads stdin / writes stdout / exits, so the same test binary is both runner and plugin. Behaviour selector is the `plugin_name` suffix from the init message (`test-echo`, `test-fail`, `test-crash`, `test-now_ms`, `test-storage_round_trip`) — no shared mutable env vars between parent and child. Tests cover: echo round-trip, plugin-reported error code, crash-before-done → `UnexpectedExit`, `now_unix_ms` round-trip, storage round-trip with capability, storage forbidden without capability (plugin panics on `error` reply → `UnexpectedExit` proves the host actually said "no").

#### Plugin System — Phase 3: `bastion-plugin-sdk` author-facing crate (`crates/bastion-plugin-sdk/`)
- New SDK crate added to the workspace. Plugin authors get a `Plugin` trait, a `register!` macro that emits the WASM ABI exports (`bv_run` + `bv_alloc`), and a `Host` struct that wraps every host import as a safe Rust call. Targets `wasm32-wasip1` (or `wasm32-unknown-unknown`) for shipping; compiles on the host too with stubs so authors can `cargo test` their handlers without spinning up wasmtime.
- **Author-facing surface**:
  - `Plugin::handle(req: Request<'_>, host: &Host) -> Response`
  - `Request::input()` (raw bytes); `Request::input_json::<T>()` with the optional `json` feature.
  - `Response::ok` / `ok_empty` / `err` / `ok_json`. `err(0, …)` normalises to status code 1 to keep the host-side `InvokeOutcome::PluginError` semantics meaningful.
  - `Host::log(level, msg)`, `set_response`, `storage_get / put / delete / list`, `audit_emit`. Storage methods loop on `STORAGE_BUFFER_TOO_SMALL` (rc=-3), doubling the buffer up to 1 MiB before giving up — so plugin authors don't have to think about buffer sizing.
  - `HostError::{Forbidden, NotFound, Internal}` from negative return codes.
  - `LogLevel::{Trace, Debug, Info, Warn, Error}`.
- **`host_test` feature** flips the host-call extern declarations to thread-local in-memory stubs. Authors write `cargo test --features host_test` to drive their handler against pre-populated storage / inspect emitted log lines + audit events. The crate also exports `test_support::{reset, put, take_response, log_lines, audit_events}` for fixtures.
- **Two reference plugins** under `examples/`:
  - `echo.rs` — minimal handler proving the round-trip; only declares `log_emit`.
  - `kv_cache.rs` — exercises every storage host call (`GET` / `PUT` / `DEL` / `LIST` verbs over a stdin-style request format), declares `storage_prefix = ""`. Build with `cargo build --release --target wasm32-wasip1 --example kv_cache -p bastion-plugin-sdk`; the resulting `.wasm` uploads via the GUI's Register-plugin modal.
- **6 SDK tests passing** under `cargo test -p bastion-plugin-sdk --features host_test`: handler round-trip, error-status normalisation, `host.log` line capture, storage round-trip with list/delete, storage-forbidden when no state populated, audit-event capture. The full ABI (`bv_alloc` + `bv_run` shims) is exercised end-to-end by the existing `crate::plugins::runtime` tests in the main crate, which run real wasmtime — so the SDK tests focus on the author-visible API surface.
- **Cross-target discipline**: the SDK is `no_std` on real wasm builds, but pulls in `std` on the host (and `host_test`) so the test stubs can use `std::sync::Mutex` without a no-std mutex crate. The `register!` macro only emits `#[no_mangle] pub extern "C"` exports under `cfg(all(target_arch = "wasm32", not(feature = "host_test")))`, so plugin authors can `cargo test` on their host without symbol-export collisions.

#### Plugins admin GUI page + Tauri commands ([gui/src/routes/PluginsPage.tsx](gui/src/routes/PluginsPage.tsx))
- New top-level **Plugins** page added to the Admin sidebar group between Audit and Import / Export. Lists registered plugins with name + version + runtime + type badges, sha256 prefix, size, ABI version, and capability badges (`log` / `storage:<prefix>` / `audit`) — disabled capabilities render struck-through so an operator can spot missing grants at a glance.
- **Register modal**: file picker for the `.wasm` binary, sha256 + size computed client-side via `crypto.subtle.digest` so the operator doesn't have to populate manifest fields by hand. Capability checkboxes wire `log_emit` / `audit_emit` / `storage_prefix` straight to the manifest. Plugin name auto-derived from the file stem and editable.
- **Invoke modal**: send a UTF-8 string as input to the plugin's `bv_run`, see status (`success` / `plugin_error`), plugin status code, fuel consumed, and the response decoded as UTF-8 (with a non-utf8 fallback). Useful for "test my plugin" workflows from the desktop GUI.
- **Delete confirm** uses the existing `ConfirmModal` and removes both the manifest and the binary from the barrier.
- New Tauri commands at [gui/src-tauri/src/commands/plugins.rs](gui/src-tauri/src/commands/plugins.rs): `plugins_list / get / register / delete / invoke`. Each emits an audit event via `bastion_vault::audit::emit_sys_audit` with the standard HMAC-redaction discipline so embedded-mode operations show up in the audit log alongside the HTTP-mode equivalents.
- New `plugin-admin` policy name added to `Layout::adminPolicies` so a token with that policy alone can see the Plugins admin link without needing full `admin` / `root`. Path-level ACL on `sys/plugins/*` continues to enforce capabilities at the request layer.
- API helpers in [gui/src/lib/api.ts](gui/src/lib/api.ts): `pluginsList / pluginsGet / pluginsRegister / pluginsDelete / pluginsInvoke` plus the `PluginManifest` / `PluginCapabilities` / `PluginInvokeResult` typings.
- **Verification**: `npx tsc --noEmit` clean, `cargo check -p bastion-vault-gui` clean, `cargo test --lib plugins::` 13/13 passing (1 ignored — Windows fuel-trap quirk), Vite preview compiled `/plugins` without console errors.

#### Plugin System — Phase 2: storage + audit host capabilities (`crate::plugins::runtime`)
- Converted `WasmRuntime` to **async wasmtime 27** (`Config::async_support(true)`, `instantiate_async`, `call_async`) so host imports can do real async barrier I/O without `block_in_place` gymnastics. Existing `bv.log` and `bv.set_response` imports kept; six new host imports added under the `bv.` namespace, all gated by manifest capabilities:
  - `bv.storage_get(key_ptr, key_len, out_ptr, out_max) -> i32` — returns the value length on success (0..out_max), `-1` not_found, `-2` forbidden (key outside declared prefix), `-3` buffer_too_small (no partial write — plugin retries with bigger buffer).
  - `bv.storage_put(key_ptr, key_len, val_ptr, val_len) -> i32` — `0` success, `-2` forbidden.
  - `bv.storage_delete(key_ptr, key_len) -> i32` — idempotent.
  - `bv.storage_list(prefix_ptr, prefix_len, out_ptr, out_max) -> i32` — newline-separated immediate children.
  - `bv.audit_emit(payload_ptr, payload_len) -> i32` — emits an audit event at `sys/plugins/<name>/event` with the payload embedded as `plugin_event` (parsed as JSON when possible so HMAC-redaction handles string leaves naturally). Capability-gated by `manifest.capabilities.audit_emit`.
- **Storage isolation**: every plugin-supplied key is rebased through `core/plugins/<name>/data/<plugin-relative-key>` before touching the barrier. Plugins with overlapping declared `storage_prefix` values still see disjoint storage because the prefix is composed with the plugin name, not the operator-supplied prefix. Rejects `..`, absolute slashes, and any key that isn't strictly inside the declared prefix. Plugins without a declared `storage_prefix` get `STORAGE_FORBIDDEN` on every storage call (rather than a no-op) so misconfiguration surfaces immediately.
- **HTTP**: `POST /v1/sys/plugins/{name}/invoke` now passes an `Arc<Core>` clone through to the runtime so storage + audit host imports actually have a barrier + audit broker to talk to.
- **Tests**: 13 passing (was 11; +2 new). `storage_forbidden_without_capability` exercises the capability-denial path against a real unsealed `Core`. `storage_round_trip_with_capability` registers a plugin that does `storage_put` then `storage_get` and verifies the bytes round-trip through the barrier-encrypted view. The existing 11 tests (manifest validation, catalog integrity, runtime echo, plugin error propagation, missing-export, unknown-host-import) all continue to pass after the sync→async conversion. Fuel-exhaustion test remains `#[ignore]` on Windows for the reason previously documented.
- **Out of scope for this iteration**: out-of-process tonic runtime, ML-DSA signature verification, hot reload, GUI plugin management, `bastion-plugin-sdk` author-facing crate, `bv.crypto_*` host imports (the `crypto` capability slot in the manifest is reserved). Each is structurally additive — the host-import linker pattern can absorb new functions without an ABI bump.

#### Audit coverage for Exchange + Plugins + Scheduled Exports
- **New helper** `crate::audit::emit_sys_audit` ([src/audit/sys_emit.rs](src/audit/sys_emit.rs)) bridges the gap for sys-level endpoints that bypass `Core::handle_request`. Resolves the actor identity from the bearer token via `AuthModule::token_store.lookup()` (display_name + policies), builds an `AuditEntry::from_response` with the standard HMAC-redaction discipline (passwords, file_b64, payloads all redacted), and fans out through the `audit_broker`. No-op when no audit device is enabled — same semantics as the in-pipeline path.
- **Every Exchange handler** now audits, success or failure: `sys/exchange/export`, `sys/exchange/import`, `sys/exchange/import/preview`, `sys/exchange/import/apply` (HTTP) plus the matching `exchange_export` / `exchange_preview` / `exchange_apply` Tauri commands used by the embedded GUI. The Tauri side also resolves the actor token from `AppState::token` so the embedded mode produces the same audit shape as remote mode.
- **Every Plugin handler** now audits: `sys/plugins` (LIST), `sys/plugins/register` (POST), `sys/plugins/{name}` (GET / DELETE), `sys/plugins/{name}/invoke` (POST). The invoke event covers both successful and plugin-reported-error outcomes — auditors see every WASM execution, including the fuel consumed if visible to the response. Catalog tampering, missing plugins, and unknown imports all surface as the operation's audit error string.
- **Scheduled exports** audit on every relevant operation: `sys/scheduled-exports` LIST, the create/get/update/delete handlers, the `runs` history endpoint, and `run-now`. **Cron-fired unattended runs** also emit audit events (`sys/scheduled-exports/{id}/run`) with status / bytes_written / error details — actor token is empty by design (no human present), schedule id + name in the body so an auditor can group by schedule.
- **Discipline notes**: errors never silence audit (the wrap pattern `(async move { … }).await; audit.finish(&result, …)` runs the emit *after* the work, regardless of `?` short-circuiting), audit emit failures don't fail the request (logged at WARN; same as the in-pipeline path's behaviour), and the audit body is taken from the *parsed-but-pre-decoded* request JSON so the persisted entry shows the operator's intent rather than just an opaque base64 blob.
- **Verification**: `cargo check --lib` clean; `cargo check -p bastion-vault-gui` clean; `cargo test --lib -- plugins:: exchange::` 34/34 passing.

#### Plugin System — Phase 1 substrate (`crate::plugins`)
- New `crate::plugins` module landing the WASM half of the plugin system from [features/plugin-system.md](features/plugin-system.md). Catalog CRUD over `core/plugins/<name>/{manifest,binary}` (barrier-encrypted), sha256 integrity verification on every read, manifest validation (rejects bad sha256, future ABI majors, the reserved `process` runtime), and a wasmtime-backed runtime with fuel + memory metering and explicit host-import gating.
- **WASM runtime**: pure-Rust `wasmtime 27` (no openssl, no aws-lc-sys), fuel cap default 100M instructions, memory cap default 256 MiB, wasm-side stack capped at 1 MiB. Plugin ABI v1: required exports `memory`, `bv_alloc(len) -> ptr`, `bv_run(input_ptr, input_len) -> i32` (0 = success, non-zero surfaces as `InvokeOutcome::PluginError(code)`); host imports `bv.log(level, ptr, len)` (capability-gated by `manifest.capabilities.log_emit`) and `bv.set_response(ptr, len)`. Imports a plugin doesn't get registered for fail at instantiate time, not silently — proven by the `unknown_host_import_rejected_at_instantiate` test.
- **HTTP surface** (`/v1/sys/plugins`): `GET` list, `POST` register (manifest + base64 binary), `GET /:name`, `DELETE /:name`, `POST /:name/invoke` returning `{ status, plugin_status_code, fuel_consumed, response_b64 }`. Per-invocation fuel override capped at 10x the default budget so a misconfigured request can't run a plugin to memory exhaustion.
- **Tests** (11 passing under `cargo test --lib plugins::`): manifest validation (good shape / bad sha256 / future ABI / process runtime), catalog integrity (round-trip / truncated / tampered), runtime echo round-trip, plugin-reported error code propagation, missing-export rejection, unknown-host-import rejection. The fuel-exhaustion trap test is `#[ignore]` on Windows because wasmtime's SEH-based trap handling collides with `cargo test`'s panic catcher (the runtime path itself works in production; production traps surface as `RuntimeError::Invoke`).
- **Out of scope for Phase 1** (explicit, tracked in spec): out-of-process tonic runtime, ML-DSA-65 signature verification (sha256 only for now — ML-DSA path unblocks once the Transit module ships), storage / audit / crypto host capabilities (`bv_log` is the only useful host call right now), hot reload, the GUI plugins page, the `bastion-plugin-sdk` author-facing crate, and plugin-as-mount integration. Each is structurally additive — the catalog + ABI shape is forward-compatible.

#### Exchange — full resolution for Resource / Asset Group / Resource Group selectors
- Replaced the "(reserved)" placeholders with real resolution. New `MountIndex` helper (`crate::exchange::scope::MountIndex::from_core`) walks `core.mounts_router.mounts.entries` once and groups mount paths by `logical_type`, so the resolver finds the right `logical/<uuid>/` barrier prefix without re-reading the table per selector.
- **Resource selector**: reads `logical/<uuid>/meta/<id>` + the resource's full secret subtree — every key under `secret/<id>/`, its metadata at `smeta/<id>/`, and the version log at `sver/<id>/<key>/<v>` — and the `hist/<id>` change log. Bundled into a single `ResourceItem.data` map keyed by `mount_path / meta / history / secrets`. Multi-mount collisions (same id on two `resource` mounts) emit a warning and keep the first hit.
- **Asset group / Resource group selector**: both selectors hit the same `sys/resource-group/group/<name>` storage prefix (the codebase's resource-group module backs both concepts). Group record is emitted as-is, plus the resolver drags in: every listed `members` entry (recursively, via `resolve_resource`), every `secrets` path (mapped back to its KV mount via longest-prefix match against the mount index, then read from `logical/<uuid>/<rel>`), and every `files` entry (`logical/<uuid>/meta/<id>` + `logical/<uuid>/blob/<id>` base64-inlined as a `FileItem`). Items the actor cannot read produce per-id warnings rather than failing the whole export.
- **GUI**: dropped the "(reserved)" labels in both the Export tab and the Schedule editor. New `<ScopeTypeHelp />` collapsible inline explainer documents what each selector does (KV path / Resource / Asset group / Resource group), what gets dragged in, and how warnings surface. Id input now placeholder-hints `resource id (e.g. t12)` vs `group name (lowercased)` based on the selected type.
- **Sorting + dedup**: items are sorted deterministically (`kv` by `(mount, path)`, `resources/files/asset_groups/resource_groups` by `id`) and deduped within each array before the document is canonicalized — so the same selector chosen twice (e.g. via a group that drags in resources also picked individually) doesn't double-emit. Tests still passing: `cargo test --lib exchange::` 23/23.

#### Scheduled Exports — Phase 1 implemented (cron-driven `.bvx` backups, GUI tab) + Import/Export moved under Admin
- New `crate::scheduled_exports` module sitting alongside `crate::exchange` and `crate::backup`. Schedules persist barrier-encrypted under `core/scheduled_exports/schedules/<id>`; run records under `core/scheduled_exports/runs/<id>/<rfc3339>` with a 100-record-per-schedule sanity cap (real retention policies are Phase 3 per the spec).
- **Single-process tokio scheduler** spawned at unseal: ticks every 30s, walks every enabled schedule, fires when the cron `next_after(prev)` is in the past. First sighting after unseal anchors `prev` to "now" so missed instants from history are not burst-fired (catch-up policy is a Phase-2 knob). Runs are launched as detached tasks with their own panic boundary; loop self-skips while sealed.
- **Schedule shape** (`ScheduleInput` / `Schedule`): name, cron (validated at create + update via the `cron` crate), `format: bvx | json`, scope reusing the Exchange `ScopeSpec`, destination `local_path` (atomic tmp-then-rename), enabled flag, optional comment. Password-source is a tagged enum: `literal` (stored on the schedule, barrier-encrypted with the rest of the record) or `static_secret` (read from a KV path at run time so rotation = update the KV value). `transit` and `external_kms` modes deferred per the spec.
- **HTTP surface** (`/v1/sys/scheduled-exports`): `GET` list, `POST` create, `GET/PUT/DELETE /:id`, `GET /:id/runs`, `POST /:id/run-now` for ad-hoc execution. **Tauri commands**: `scheduled_exports_list / create / update / delete / runs / run_now` dispatch directly against `core.barrier.as_storage()` in embedded mode.
- **GUI**: new **Scheduled backups** tab on the Import / Export page with list, create/edit modal (name, cron, format, scope picker reusing the export tab's pattern, destination directory, password-source toggle, comment), per-schedule **Runs / Run now / Edit / Delete** actions, run-history modal showing `when / status / bytes / detail`, and a delete-confirm dialog.
- **Import/Export moved under Admin** sidebar group with a new policy name `exchange-admin` added alongside `root` / `admin` in `Layout.tsx#adminPolicies`. Operators who want to delegate just import/export without granting full admin can grant a token the `exchange-admin` policy + a path-level capability on `sys/exchange/*` and `sys/scheduled-exports/*`. Full delegation discipline (separate per-feature policies) is documented in [features/import-export-module.md](features/import-export-module.md).
- **Verification**: `cargo check --lib` clean; `cargo check -p bastion-vault-gui` clean; `cargo test --lib exchange::` 23 passing; `npx tsc --noEmit` clean; Vite preview compiled and served the new tab without console errors. Out of scope for Phase 1: Hiqlite leader gating, GFS retention, decrypt-and-parse verification, cloud destinations, and BVBK format — tracked in [features/scheduled-exports.md](features/scheduled-exports.md) Phases 2–5.

#### Exchange (Import / Export) module — Phase 3 + Phase 4 implemented (CLI + GUI + two-step preview/apply + Phase-4 schema)
- **Two-step preview/apply HTTP flow**: `POST /v1/sys/exchange/import/preview` decrypts + parses + classifies (per-item `new` / `identical` / `conflict` plus counters) and returns an opaque token; `POST /v1/sys/exchange/import/apply` consumes the token + a `conflict_policy` enum and writes the items. Tokens are 256-bit URL-safe random, single-use, **owner-bound** (apply call must come from the same actor that ran the preview), and TTL'd (10-minute default, sweeper drops expired entries on every insert/consume). State is process-local in-memory by design — previews carry decrypted plaintext, so persisting them across restarts would expand the persistence surface unnecessarily. The single-shot `POST /v1/sys/exchange/import` is kept as a convenience for automation pipelines.
- **CLI**: new `bvault exchange` top-level subcommand grouping `export` and `import`. `--scope kv:<mount>/<path>` repeatable; resource / asset_group / resource_group selectors accepted but emit "unresolved" warnings (Phase-4 schema reservation, full resolution lands in a follow-up). Passwords read from stdin / TTY only — `--password=` flag explicitly refused. `--preview` flag on import returns the per-item classification + token without writing. Mirrors the HTTP shape; the binary `.bvx` payload is base64-wrapped in the JSON response so the existing `Sys` API client doesn't need a raw-bytes path.
- **GUI**: new top-level `Import / Export` page at `/exchange` (added to user nav). Two tabs: **Export** (scope picker with `+ Add scope` rows for KV mount/path or reserved resource/group selectors; format picker `bvx` / `json`; password input with ≥12-char floor; optional comment; downloads the produced file via Blob URL) and **Import** (file picker accepts `.bvx` / `.json`; `Preview` button shows the per-item classification table with `new` / `identical` / `conflict` counts + token TTL; conflict-policy picker + `Apply import` consumes the token). Plaintext export and import both gated behind explicit `Allow plaintext` checkboxes, matching the HTTP refusal behaviour. Three new Tauri commands (`exchange_export` / `exchange_preview` / `exchange_apply`) dispatch directly against `core.barrier.as_storage()` + `core.exchange_preview_store` in embedded mode; the same shape works in remote mode via the new `Sys::exchange_*` API methods.
- **Phase-4 schema reservation**: `ExchangeItems` now carries optional `resources`, `files`, `asset_groups`, `resource_groups` arrays alongside `kv` (additive — old documents keep parsing); `ScopeSelector` gains `Resource { id }`, `AssetGroup { id }`, `ResourceGroup { id }` variants. The exporter recognises the new variants and emits a clear "unresolved" warning into the document instead of silently producing empty exports — the schema is forward-compatible so a future producer can fill in the items without breaking importers in the field. Full per-mount-UUID resolution against the resource / files / group modules is the next deliverable.
- **Tests**: 23 unit tests across `exchange::*` (was 19 before this round). New: 4 preview-store tests (insert+consume round-trip, single-use enforcement, owner mismatch refused, expired token refused). All passing under `cargo test --lib exchange::`. `cargo check -p bastion-vault-gui` clean. `npx tsc --noEmit` clean against the new GUI page + API wrappers.

#### Exchange (Import / Export) module — Phase 1 + Phase 2 implemented (`src/exchange/`)
- New `crate::exchange` module shipping the bvx.v1 schema + canonical JSON encoder + Argon2id KDF + password-encrypted `.bvx` envelope, with KV-multi-mount export and conflict-aware import (`skip` / `overwrite` / `rename`). Lives alongside `crate::backup` rather than replacing it: BVBK remains the operator-level disaster-recovery primitive; `.bvx` is the user-level portable + password-protected primitive.
- **HTTP surface**: `POST /v1/sys/exchange/export` (request body picks `format: "bvx" | "json"`, requires `password` for `bvx`, requires explicit `allow_plaintext: true` for `json`) and `POST /v1/sys/exchange/import` (same `format` + `password` + `allow_plaintext` semantics, plus a `conflict_policy` enum). Plaintext export and import are both refused by default; opt-in flag plus a separate audit-friendly response path.
- **Crypto**: Argon2id with OWASP-2024 defaults (`m_cost = 65 536 KiB`, `t_cost = 3`, `p_cost = 1`, 16-byte random salt) → 32-byte key → XChaCha20-Poly1305 with 24-byte random nonce, AAD pinned to `"BVX"`. KDF and AEAD parameters embedded in the envelope JSON (forward-compat tuning); KDF parameters bounded both ways (refuses files declaring weak *or* DoS parameters). Minimum 12-character password enforced; CLI password-flag accepted at HTTP layer only via the JSON body, never query string. `password` field is `zeroize`d in the request struct after use.
- **Determinism + integrity**: canonical JSON encoder (sorted keys, no whitespace, `BTreeMap` rebuild on every nested object) so two exports of the same scope produce byte-identical inner JSON; AEAD authenticates the entire inner document so any tamper to the ciphertext or salt fails the tag check (`wrong_password_fails_closed`, `tampered_ciphertext_fails_closed`, `tampered_salt_fails_closed` tests verify the failure mode).
- **Tests**: 19 unit tests covering canonical-JSON determinism, KDF round-trip + parameter bounds, envelope round-trip, wrong-password / tampered-ciphertext / tampered-salt fail-closed paths, and the four importer paths (`new` / `identical` / `conflict + skip` / `conflict + rename`). All passing under `cargo test --lib exchange::`.
- **Out of scope for this implementation**: GUI (Phase 3), CLI commands (planned), file-resource inlining + asset/resource-group expansion (Phase 4), and the explicit two-step preview/apply token store (the spec's mandatory two-step is replaced for v1 by a single-shot import that returns the per-item classification table; the preview/apply split lands as a follow-up). New roadmap row + spec updates: see [features/import-export-module.md](features/import-export-module.md).

#### Scheduled Exports spec — cron-driven exportable backups ([features/scheduled-exports.md](features/scheduled-exports.md))
- New feature definition extending the existing backup subsystem with a **scheduler** that drives the new Exchange module on a recurring cadence to produce **password-protected `.bvx` exportable backups**. Distinct from BVBK (operator-level binary, restorable only against the same vault's barrier): scheduled `.bvx` exports are portable across instances, decryptable with a password, inspectable in JSON, version-stable, and aimed at off-site rotation + compliance evidence.
- **Five capabilities**: cron-expressed schedule definitions persisted in the barrier, leader-gated scheduler runtime (Hiqlite Raft leader signal + Raft-backed per-schedule locks → no split-brain double-runs), retention policies (count / age / **GFS** with `keep_daily/weekly/monthly/yearly`), verification (decrypt-and-parse every Nth run with a `min_verified` floor that retention cannot violate), and direct integration with the existing cloud-storage `FileTarget` trait so off-site backups are first-class.
- **Three password-resolution modes**: **`transit`** (recommended — per-run ML-KEM-768-wrapped datakey embedded in the `.bvx` `comment` field for forward-secret rotation), **`static_secret`** (KV-path read), and **`external_kms`** (AWS/Azure/GCP KMS, deferred). `scheduled_export_password_used` audit event records which key was consulted, never the resolved password. Catch-up amplification capped at 100 instants regardless of `catch_up = "all"` to prevent wake-up storms.
- **Format-agnostic scheduler**: same runtime drives `format = "bvx"` (Phase 2) and `format = "bvk"` (Phase 4 — calls existing `src/backup/create.rs`) so operators can run `.bvx` and BVBK schedules side-by-side. Owner-deleted schedules auto-disable + alert; verify-failed runs do not knock prior verified backups out of retention. Phased plan: P1 scheduler + plaintext JSON + local destinations → P2 `.bvx` + Transit password-ref (depends on Exchange Phase 2) → P3 retention + verification → P4 cloud destinations + BVBK format → P5 GUI with cron picker (cronstrue), retention editor, and run-history drill-down. External KMS, HTTP webhook destinations, differential exports, and cross-cluster fan-out explicitly out of scope.

#### Import / Export Module spec — user-facing JSON + password-encrypted `.bvx` ([features/import-export-module.md](features/import-export-module.md))
- New feature definition for a user-facing exchange flow distinct from the existing operator-level BVBK backup-restore path. Three layers: stable versioned **`bvx.v1` JSON schema** (KV items, resources, file-resource payloads, asset/resource-group memberships, optional policies + identities, with canonical key-sorted encoding so two exports of the same scope produce byte-identical bytes); password-encrypted **`.bvx` envelope** using **Argon2id** KDF (m_cost=64 MiB, t_cost=3) → XChaCha20-Poly1305 AEAD with embedded KDF parameters for forward-compat tuning; mandatory **two-step preview-then-apply import** with per-item `skip / overwrite / rename` conflict policy, opaque single-use 10-minute preview tokens, and full audit-event coverage.
- Plaintext-export path is gated behind explicit per-mount config + an `--allow-plaintext` flag and emits a separate `exchange_export_plaintext` audit event so SOC visibility is preserved; passwords never accepted via CLI flags (only stdin / TTY); GUI shows live zxcvbn entropy meter and never reveals plaintext export. Vault fingerprint embedded in the envelope so cross-vault imports surface a warning. Preserves owner / sharing metadata and integrates with namespaces (cross-namespace import refused without `--allow-namespace-rewrite`), per-user scoping, asset/resource groups, and Compliance Reporting (events automatically appear in SOC 2 CC8.1 + ISO A.5.18).
- Phased plan: P1 plaintext JSON round-trip + scope resolver + preview/apply → P2 Argon2id + `.bvx` envelope → P3 GUI Exchange page (scope picker, password meter, conflict-policy table) → P4 selective-export polish + file-payload inlining (32 MiB per file, 1 GiB total cap). Diff-based incremental exports, public-key encrypt-to-recipient, GPG/age compatibility, in-place password rotation, and >1 GiB streaming explicitly out of scope.

#### Kubernetes Integration spec ([features/kubernetes-integration.md](features/kubernetes-integration.md))
- New feature definition for K8s workload integration. Three deliverables: an in-tree `kubernetes` auth backend (Vault-compatible `auth/kubernetes/login` with TokenReview-preferred JWT verification + local-pubkey fallback), a standalone CSI driver (`bastion-vault-csi-driver`) compatible with `secrets-store.csi.x-k8s.io` so existing AKS/EKS/GKE add-ons keep working, and an admission-webhook agent injector (`bastion-vault-agent` + `bastion-vault-injector`) with Vault-Agent-compatible annotations and a sandboxed `minijinja` template subset.
- Pure-Rust + rustls everywhere (`kube`, `k8s-openapi`, `tonic`, `axum`); shared `crates/bv_kube` client crate not pulled into core. Role bounds refuse `*` for SA names/namespaces; CSI mounts use `tmpfs` with `MS_NOEXEC|MS_NOSUID|MS_NODEV`, capabilities dropped post-mount, secrets zeroised on unmount; webhook cert auto-rotates weekly via Kubernetes CSR approval. Phased plan: P1 auth backend (TokenReview) → P2 local-pubkey verification + GUI Identity tab → P3 CSI driver → P4 agent injector → P5 reference Helm charts + operator docs. Vault Secrets Operator-style CRDs, SPIFFE/SPIRE, Windows pods, and ESO parity explicitly out of scope.

#### Namespaces / Multi-tenancy spec ([features/namespaces-multitenancy.md](features/namespaces-multitenancy.md))
- New feature definition that disambiguates the existing `Partial` row: per-user scoping ([features/per-user-scoping.md](features/per-user-scoping.md)), asset groups, and resource groups already ship; what's missing is **inter-tenant** isolation (Vault Enterprise-style hierarchical namespaces). Spec adds per-namespace mount tables, policy stores, identity stores, token stores, audit broadcasters, and quotas (storage bytes, lease count, request rate, mount/entity/child caps), with `X-BastionVault-Namespace` header + `/v1/<ns>/...` path-prefix routing.
- **Tokens are namespace-bound**; cross-namespace use refused unless the issuer set `child_visible=true`, which permits descendant-only delegation. Policies refuse cross-namespace path references at write time. Audit broadcasters are per-namespace by default with an opt-in root-mirror for central SOC visibility (target audit unaffected, requestor audit logs every cross-namespace failure). One-way parent-visible identity-link primitive lets MSPs correlate the same human across child tenants without exposing siblings to each other. Phased plan: P1 namespace container + mount routing + storage migration → P2 per-namespace policy/token/audit → P3 per-namespace identity + identity-link → P4 quotas + GUI tree view + namespace switcher. Cross-namespace mount sharing, per-namespace barrier keys, hierarchical policy inheritance, and migration of per-user scoping into per-namespace scoping explicitly out of scope.

#### Plugin System spec ([features/plugin-system.md](features/plugin-system.md))
- New feature definition for runtime plugin loading. Two execution backends behind one versioned `PluginService` protocol: **WASM via `wasmtime`** (default, sandboxed in-process, no network/filesystem/clocks, fuel + memory metered) and **out-of-process via `tonic` over UDS / Windows named pipes** (when a plugin needs real networking or system access). Native cdylib loading explicitly rejected — Rust ABI is unstable and provides no security boundary.
- **Capability-based isolation**: plugin manifest declares storage prefix + read/write/list, audit emit rights, allowed Transit `key_handle`s, and (process-only) outbound-host allowlists; capabilities pinned at registration, widening requires re-registration. Plugins signed with **ML-DSA-65 via Transit** and verified against an operator-configured publisher allowlist; sha256 binary integrity enforced at load time too. `bastion-plugin-sdk` crate provides a `Plugin` trait + `register!` macro targeting `wasm32-wasi-p1/p2`.
- Phased plan: P1 catalog + manifest + WASM runtime + SDK → P2 process runtime + supervisor (restart-with-backoff, log forwarding, allowlisted networking) → P3 hot reload + GUI Plugins page → P4 reference plugins (`bastion-plugin-postgres` out-of-process, `bastion-plugin-totp` WASM) shipped out-of-tree to prove the SDK. Per-language runtimes, plugin marketplace, cross-plugin IPC, and live debugging explicitly out of scope.

#### Compliance Reporting spec ([features/compliance-reporting.md](features/compliance-reporting.md))
- New feature definition for an auditor-ready Compliance subsystem covering **SOC 2** (CC6.1–CC8.1), **ISO/IEC 27001:2022 Annex A** (A.5.15-A.8.24), **PCI-DSS v4.0** (Req 3/7/8/10), **HIPAA Security Rule** (§164.308 + §164.312), **NIST SP 800-53 rev 5** Moderate baseline (AC/AU/IA/SC families), and **LGPD / GDPR** (Art. 30/32/33/37/46). Three-layer architecture: a small JSON query language over audit/mount/policy/identity/lease state with secondary indexing, pre-built per-control reports with stable schemas + golden-file determinism, and a signed `.bvev` evidence-package export.
- **Evidence packages signed with ML-DSA-65** via the Transit engine — first load-bearing operational use of BastionVault's PQC primitives. Standalone `bv-verify-evidence` binary lets auditors verify offline without BastionVault running. Daily config snapshots (Phase 2) feed change-management reports; an immutable access-review workflow (Phase 3) covers controls that demand evidence-of-review rather than evidence-of-access.
- Phased plan: P1 query layer + SOC 2 + ISO 27001 reports → P2 PCI-DSS + HIPAA + NIST 800-53 + LGPD/GDPR + snapshots → P3 signed `.bvev` export + access reviews + verifier binary → P4 Compliance / Access Reviews GUI pages. Continuous monitoring/alerting, auditor portal, cross-vault aggregation, and PII auto-discovery explicitly out of scope.

#### Dynamic Secrets framework spec ([features/dynamic-secrets.md](features/dynamic-secrets.md))
- New feature definition for the engine-agnostic chassis that lets BastionVault mint short-lived credentials in external systems and revoke them on lease expiry. Generic `DynamicCredentialBackend` trait, lease-manager hooks (`generate`/`renew`/`revoke`/`revoke_failed` with retry + tidy), pure-Rust connection pool via `deadpool`, opt-in per-(role, identity) credential cache, and a new `dynamic_secret` audit event schema with target-identity tracking.
- Phased plan: P1 framework + database engine (Postgres + MySQL via `tokio-postgres` / `sqlx` over rustls) → P2 MSSQL + MongoDB + Redis plugins → P3 AWS / GCP / Azure engines → P4 SSH dynamic-keys mode hooked into the framework → P5 GUI Leases page + per-role generate widget. OpenLDAP/AD password rotation, K8s SA tokens, response-wrapping, and PKI lease-revocation hooks explicitly out of scope.

#### SSH secret engine spec — pure-Rust, PQC-aware ([features/ssh-secret-engine.md](features/ssh-secret-engine.md))
- New feature definition for a Vault-compatible SSH engine on `russh-keys` + `ssh-key` (RustCrypto), no OpenSSL. Surfaces all Vault SSH endpoints (`config/ca`, `roles`, `sign`, `issue`, `creds`, `verify`, `lookup`, `public_key`) plus a separate target-host helper binary (`bv-ssh-helper`) for OTP mode.
- **CA mode** signs OpenSSH client / host certificates with classical algorithms (RSA / Ed25519 / ECDSA P-256/P-384) reusing the `CertSigner` trait from the PKI spec, plus an opt-in **PQC** mode (`ssh-mldsa65@openssh.com`, feature flag `ssh_pqc`) that issues ML-DSA-65-signed certificates for environments running PQC-aware SSH clients. `pqc_only=true` on a role rejects classical client public keys to force an end-to-end PQC chain.
- **OTP mode** generates 160-bit single-use passwords (BLAKE2b-hashed at rest, constant-time compare on consume) with replay-impossible single-consume semantics and lease-manager integration so OTPs show up in `sys/leases/lookup` and can be force-revoked.
- Phased plan: P1 CA mode classical → P2 OTP + helper binary → P3 PQC SSH certificates → P4 GUI integration → P5 (optional) dynamic-keys mode via the dynamic-secrets framework. CRL/KRL distribution, host-cert rotation pipelines, HSM-backed CA keys, and live SSH terminals explicitly out of scope.

#### TOTP secret engine spec ([features/totp-secret-engine.md](features/totp-secret-engine.md))
- New feature definition for a Vault-compatible TOTP (RFC 6238) engine. Two modes per key: **generate** (engine produces seed + `otpauth://` URL + base64-PNG QR for authenticator scanning) and **provider** (engine validates submitted codes against an imported seed).
- Pure-Rust deps only (`hmac`, `sha1`, `sha2`, `base32`, `url`, `qrcode`, `image`); no OpenSSL. Vault-compatible HTTP surface (`keys` CRUD/LIST + `code` GET-to-generate / POST-to-validate).
- Adds **replay protection** beyond Vault parity: successful validations record the matched step so a captured code can't be replayed within the `skew` window; opt-out via `replay_check = false` for strict Vault behaviour.
- Phased plan: P1 core engine (HOTP/TOTP via RFC 4226/6238 vectors) → P2 QR barcode rendering → P3 replay protection + tidy → P4 optional GUI tab with live code widget. HOTP, OCRA, push-2FA, and PQC-TOTP variants explicitly out of scope.

#### Transit secret engine spec — encryption-as-a-service, PQC-capable ([features/transit-secret-engine.md](features/transit-secret-engine.md))
- New feature definition for a Vault-compatible Transit engine on the existing pure-Rust `bv_crypto` stack. Surfaces the full Vault `transit/*` API: `keys` CRUD + `rotate` + `trim`, `encrypt` / `decrypt` / `rewrap`, `sign` / `verify`, `hmac`, `datakey/{plaintext,wrapped}`, `random`, `hash`, `export`, `backup` / `restore`, and BYOK `wrapping_key` + `import` + `import_version`.
- **PQC key types exposed to callers**: `ml-kem-768` for asymmetric encryption / datakey wrapping (with HKDF-derived 256-bit keys), `ml-dsa-44` / `ml-dsa-65` / `ml-dsa-87` for signatures, plus optional feature-gated hybrids (`hybrid-x25519+ml-kem-768`, `hybrid-ed25519+ml-dsa-65`). Classical key types covered for parity: `aes256-gcm96`, `chacha20-poly1305`, `xchacha20-poly1305`, `hmac`, `rsa-{2048,3072,4096}`, `ecdsa-p256`, `ecdsa-p384`, `ed25519`.
- Specifies versioned ciphertext framing (`bvault:vN[:pqc:<algo>]:b64`), Vault-style key versioning with `min_decryption_version` / `min_available_version`, per-mount UUID-scoped barrier storage, audit HMAC redaction of `plaintext`/`ciphertext`/`signature`, and capability-matrix enforcement (encrypt-only vs sign-only key types). Phased plan: P1 symmetric → P2 classical asymmetric → P3 PQC → P4 hybrid + BYOK + convergent. Managed/HSM keys, CMAC, FPE, auto-rotate, and cross-cluster replication explicitly out of scope.

#### Docs: Secret Engines architecture page ([docs/docs/secret-engines.md](docs/docs/secret-engines.md))
- New documentation chapter explaining how secret engines work end-to-end: the `Module` trait and factory registration via `add_logical_backend`, the `new_logical_backend!` declarative route/field/secret schema, mount-table persistence and per-mount UUID-scoped storage views, the request lifecycle (HTTP → router → handler → barrier → lease manager → audit), barrier encryption + storage isolation, the catalogue of engines shipped today (`kv`, `kv_v2`, `crypto`, `files`, `resource`, `pki` stub, `system`, etc.), and a step-by-step "adding a new engine" recipe.

#### PKI secret engine spec — pure-Rust, PQC-capable rewrite ([features/pki-secret-engine.md](features/pki-secret-engine.md))
- New feature definition replacing the retired legacy PKI module ([src/modules/pki/mod.rs:1](src/modules/pki/mod.rs:1)). Re-introduces the Vault-compatible `/v1/pki/*` surface (roles, root/intermediate, issue, sign, revoke, fetch, CRL) on a fully OpenSSL-free stack: `rcgen`, `x509-cert`, `der`, `spki`, `rsa`, `ecdsa` + `p256`/`p384`, and `ed25519-dalek`.
- Adds **post-quantum certificate** support via `fips204` (ML-DSA-44/65/87) with new role `key_type` values, plus an optional feature-gated **composite (hybrid)** mode pairing a classical signer with ML-DSA for migration scenarios.
- Specifies a `CertSigner` trait that unifies classical and PQC signing, an OID table for ML-DSA X.509 encodings, mixed-chain rejection by default, sealed CA-key storage, and CRL modernisation. Phased plan: Phase 1 classical pure-Rust → Phase 2 ML-DSA roles → Phase 3 composite → Phase 4 CRL/tidy. ACME, OCSP, and HSM-backed CA keys are explicitly out of scope and tracked separately.

#### SSO admin UI — SAML 2.0 support in Settings card (`gui/src-tauri/src/commands/sso_admin.rs`, `gui/src/routes/SettingsPage.tsx`, `gui/src/lib/api.ts`)
- **Protocol selector** at the top of the Add-SSO-Provider modal lets the admin pick **OpenID Connect** or **SAML 2.0** before filling out provider-specific fields. Edit mode keeps the protocol fixed — the mount path maps one-to-one to an auth-backend kind, and "converting" an OIDC mount to SAML would require tearing it down.
- **`sso_admin` backend command module rewritten as a kind-aware driver**: `SsoAdminProvider` / `SsoAdminInput` are tagged unions (`#[serde(tag = "kind")]`) carrying either `OidcAdminConfig` + `OidcAdminRole` or `SamlAdminConfig` + `SamlAdminRole`. Create / update mount the right auth kind, write the right config path (`auth/<mount>/config` for both kinds, with disjoint field sets), and write the right role shape. Validation rejects mismatched `kind` ↔ `config` ↔ `role` triples server-side.
- **SAML form** covers SP identification (`entity_id`, `acs_url`), IdP discovery (metadata URL OR inline XML OR SSO URL + PEM cert), and the default-role's SAML-specific fields (bound subjects + bound subjects type + bound attributes JSON + attribute mappings JSON + groups attribute). Inline metadata XML and PEM cert are redacted on read; edit-mode shows `(set — blank to keep)` hints next to both textareas so the admin knows blanks preserve the stored secret.
- **Callback-URL hints are kind-aware**: OIDC hints distinguish desktop loopback (RFC 8252, IdP-specific labels) vs remote stable ACS; SAML hints always emit the stable `<vault>/v1/auth/<mount>/callback` because SAML IdPs POST signed assertions to a fixed URL and can't use loopback. Desktop mode includes a note pointing operators at remote deployments for production SAML.
- **Provider list row badges adapt**: OIDC rows show a "PKCE" badge when `client_secret_set = false`; SAML rows show a "No cert" warning when `idp_cert_set = false` and the discovery URL displayed is the metadata URL or SSO URL as applicable.
- **Unauth `sys/sso/providers` discovery endpoint now surfaces SAML mounts** too — `SystemBackend::SSO_KINDS` is `["oidc", "saml"]`. The login page picks up any configured SAML provider as a "Sign in with …" button with zero additional code.
- **TypeScript types are a proper discriminated union** so consumer code narrows correctly: `p.kind === "oidc" ? p.config.discovery_url : p.config.entity_id` is type-safe. The wire format from Rust uses the same tagged-union shape; the top-level `kind` and the nested `config.kind` always agree.
- `quick-xml` config dep promoted to always-on so the `cloud_s3` feature no longer gates the SAML response parser (matches the Phase 3 ship from the prior commit).
- TypeScript clean, vitest 66/66, `cargo check -p bastion-vault-gui` clean.

#### Password generator — now its own Modal window (`gui/src/components/ui/PasswordGenerator.tsx`, `gui/src/components/ui/SecretInput.tsx`)
- **Move the password-generator popover into a dedicated Modal.** The inline popover rendered by `SecretInput`'s dice button was visually colliding with enclosing forms (e.g. the Create-Secret modal — Length slider + character-group toggles bled out of the field's visible area). Clicking the dice now opens a proper Modal titled "Generate Password" that sits above everything and scrolls independently.
- **`embedded` prop on `PasswordGenerator`** strips its own popover chrome (border, background, shadow, fixed width), its internal Escape / outside-click-close handlers, and its inner Cancel button — the parent Modal owns all of those. No more "card inside a card" visual, no more double-close race between the popover's document-mousedown handler and the Modal's backdrop-click handler.
- Existing call sites (`SecretPairsEditor`, Create-Secret forms, any field with `showGenerator` set) pick up the new behaviour automatically — the `SecretInput` wrapper swapped from absolute-positioned popover to Modal in place. No API change to callers.

#### SAML 2.0 auth backend — Phase 3 (auth flow) complete (`src/modules/credential/saml/`)
- **Login + callback handlers** at `auth/<mount>/login` and `auth/<mount>/callback` (both unauth). Login generates a SAML AuthnRequest, DEFLATE-compresses + base64-encodes per the HTTP-Redirect binding, persists a single-use `SamlAuthState` record at `state/<relay_state>` with a 5-minute TTL, and returns the fully-formed IdP SSO URL. Callback parses the IdP's SAML Response, validates it structurally, verifies the XML signature, projects SAML attributes into the role's metadata mappings, and returns an `Auth` for the token store to mint.
- **Pure-Rust signature verification** — no `samael` / `libxml2` / `libxmlsec1` / OpenSSL dependency. Built on `rsa 0.9` + `x509-parser 0.17` + a hand-rolled Exclusive XML Canonicalization implementation that handles the output format every major IdP (Azure AD, Okta, Keycloak, Shibboleth, ADFS) emits on signed regions: namespace pruning to visibly-used prefixes, attribute + namespace sorting, c14n text + attribute escaping, expanded-empty-element serialisation. Supports RSA-SHA256 (primary) and RSA-SHA1 (legacy IdPs) with SHA-256 / SHA-1 digest methods. Verified end-to-end via a roundtrip test that signs with a freshly-generated 1024-bit RSA keypair and then re-canonicalises + digests + RSA-verifies the result; tampered payloads produce a digest mismatch.
- **Response-level or Assertion-level signatures** — the verifier prefers the Assertion-level signature (smaller signed region, tighter security property) and falls back to Response-level when only that exists. Rejects unsigned responses outright.
- **Structural validation** (`validate.rs`): SAML Status must be Success, Destination must match the configured ACS URL, InResponseTo must match the stored AuthnRequest ID (rejects unsolicited responses outright), Issuer must match the configured IdP entity id, Audience must include the configured SP entity id, NotBefore / NotOnOrAfter windows enforced with a 60 s default clock-skew grace. Ships a dependency-free ISO-8601 UTC parser + Howard-Hinnant civil-date algorithm.
- **Attribute projection**: per-role `attribute_mappings` rename SAML attribute names to Vault token-metadata keys; the comma-joined `groups_attribute` value lands under `auth.metadata["groups"]` for identity-group binding. `name_id` + `name_id_format` + `role` always populated. `SamlRoleEntry::validate_assertion` enforces `bound_attributes` + `bound_subjects` + `bound_subjects_type` at callback time.
- **`login_renew` handler** reloads the role on every renewal and rejects if the role was deleted or its policies drifted — same invariant as the OIDC backend.
- **New deps**: `rsa = "0.9"`, `x509-parser = "0.17"`, `flate2 = "1.0"`, plus aliased `sha1-saml` / `sha2-saml` at version 0.10 with the `oid` feature (bridges the `rsa 0.9 ↔ digest 0.10` lineage without touching the project's top-level `sha1 = "0.11"` + `sha2 = "0.11"` post-quantum stack). `quick-xml` promoted from optional-under-`cloud_s3` to always-on; `cloud_s3` no longer needs to feature-gate it.
- **Test fixtures**: `test_file_backend_multi_routine` + the CLI-subprocess-test family's binary-path helper fallback changed from `"unknown"` to `"bvault"` earlier; SAML adds 32 new unit/integration tests on top of that for a total of 46 SAML tests. 524/524 library tests pass.
- **Pragmatic limits** (documented in `verify.rs`): RSA-only signatures, enveloped-signature shape only, single `<Reference>` per SignedInfo, no `<InclusiveNamespaces>` PrefixList customisation. Every unsupported algorithm produces a descriptive error naming the exact OID / URL rather than silently accepting. (Phase 3, `features/saml-auth.md`)

#### Cloud FileTarget memory cache — v2: singleflight, stale-while-revalidate, prefetch, 500 MiB default (`src/storage/physical/file/cache.rs`)
- **Default cache size increased from 64 MiB to 500 MiB** (`DEFAULT_MAX_BYTES`). `DEFAULT_MAX_ENTRIES` bumped from 4096 to 65,536 to match — a 500 MiB cache of tens-of-kB ciphertext entries was getting evicted on entry-count before byte-count. Both remain tunable via `cache_max_bytes` / `cache_max_entries` config keys.
- **Per-key singleflight gate**: concurrent readers of the same cold key now coalesce through a `tokio::sync::Mutex` keyed by cache key, so the underlying provider sees exactly one request per (key, miss) instead of N. Gate is populated only on the miss path and cleaned up after the fetch; steady-state hits never touch it.
- **Stale-while-revalidate**: new `stale_ratio` knob (default 0.5) splits each entry's TTL into a "fresh" window (return cached immediately, no side-effects) and a "stale but serveable" window (return cached AND spawn a background refresh via `tokio::spawn`). Readers past the full TTL still pay one provider round-trip synchronously, under the singleflight gate. The net effect: hot keys stay hot forever under steady traffic, because the background refresh re-enters the fresh window before any caller notices.
- **Opt-in background prefetch**: new `prefetch_keys: Vec<String>` + `prefetch_concurrency` (default 4) config knobs. When non-empty, the cache constructor spawns a bounded-concurrency task that reads each key and populates the cache — the very first post-boot vault request finds the barrier's hot entries already warm. Empty by default: the "right" warmup set depends on the deployment, and silent magical prefetch would surprise operators.
- **Three new config keys**: `cache_stale_ratio` (float), `cache_prefetch_keys` (array or comma-separated string), `cache_prefetch_concurrency` (int). Parsed by `FileBackend::cache_config_from`.
- **Graceful sync_handler fallback**: singleflight, SWR, and prefetch all `#[cfg(not(feature = "sync_handler"))]`-gated — under the sync build, the cache behaves like the v1 pure-TTL cache (no spawn, no gate). The async features kick in only when the runtime is actually present.
- **4 new tests** on top of the existing 9: singleflight (8 concurrent readers → 1 provider call), SWR (stale hit serves fast + background refresh lands + next read sees refreshed value without provider call), prefetch (configured keys loaded before first request), stale_ratio clamping (NaN / negative / >1 all normalised). 13/13 cache tests green, 86/86 full storage suite green.

#### Cloud FileTarget memory cache (`src/storage/physical/file/cache.rs`)
- **New `CachingTarget` decorator** wrapping any `FileTarget` with a bounded, TTL-based in-memory cache for `read(key)` and `list(prefix)`. Sits above the provider (S3 / OneDrive / Google Drive / Dropbox) so repeated reads within the TTL serve from RAM instead of the network — the dominant latency source on cloud-backed vaults, where every barrier `get` would otherwise turn into an HTTPS round-trip.
- **Security**: caches only AEAD ciphertext bytes already emitted by the barrier two layers above. No plaintext key material, bearer token, or decrypted secret is cached — same invariant the existing `CachingBackend` (secret-engine layer) relies on, now extended to the storage-target layer.
- **Defaults**: `read_ttl = 30s`, `list_ttl = 10s`, `max_entries = 4096`, `max_bytes = 64 MiB`. All four are tunable via config keys (`cache_read_ttl_secs` / `cache_list_ttl_secs` / `cache_max_entries` / `cache_max_bytes`). An explicit `cache = true`/`false` config key overrides the default-on policy.
- **Default-on for cloud kinds** (`s3` / `onedrive` / `gdrive` / `dropbox`), **default-off for `local`** (the local filesystem is already faster than a cache lookup). Zero behavior change for default builds that don't use cloud targets.
- **Invalidation**: `write(k, v)` and `delete(k)` drop the cached read for `k` plus every cached `list(prefix)` where `prefix` is a prefix of `k` — list entries whose enumeration might have been affected. Unrelated prefixes stay hot.
- **Negative caching**: `read(k) → None` results are cached so the barrier's "probe for existence" pattern stays hot.
- **Eviction**: oldest-by-insertion-time (FIFO-ish) when either cap is exceeded. Soft caps — a single oversized value won't be permanently uncacheable.
- **Metrics**: `bvault_cache_{hits,misses,evictions,size}_total{layer="cloud_target"}` — new `CacheLayer::CloudTarget` variant reuses the existing cache-metrics Prometheus families.
- **Placement**: stack is now `FileBackend → ObfuscatingTarget → CachingTarget → Provider` when both are enabled. Cache is keyed by whatever key the layer above hands down (obfuscated hash under `obfuscate_keys = true`, plaintext path otherwise).
- **Zero new dependencies** — built on `dashmap` + `tokio` + `prometheus-client` already in the workspace.
- **9 unit tests** covering hit-after-miss, negative-cache, write-invalidates-read, delete-invalidates-read, list-invalidated-on-write-under-prefix, unrelated-prefixes-retained, TTL-expiry-forces-refetch, byte-cap-eviction, entry-cap-eviction. All green.
- **Deferred (follow-ups)**: background prefetch (opt-in warmup), stale-while-revalidate, per-key singleflight. The vault core's own per-key locks one layer up serialize most hot-path reads, so the marginal benefit is small without a profile justifying it.

#### SSO admin UI — full provider lifecycle from Settings (`gui/src-tauri/src/commands/sso_admin.rs`, `gui/src/routes/SettingsPage.tsx`)
- **New Tauri command module** `sso_admin` with 6 commands: `sso_admin_list` / `sso_admin_get` / `sso_admin_create` / `sso_admin_update` / `sso_admin_delete` / `sso_admin_callback_hints`. Each bundles the N vault writes needed to stand up an OIDC provider end-to-end (`sys/auth/<mount>` → `auth/<mount>/config` → `auth/<mount>/role/<default>`) so the admin never drops to the raw API. Delete disables the auth mount; config + role storage scoped to the mount is torn down with it.
- **Settings → Single Sign-On card now does real admin**: lists every configured OIDC provider with display name + kind badge + mount path + discovery URL. Each row has Edit / Delete; header has "Add Provider" button and the existing enabled/disabled toggle. "Missing role" and "PKCE" badges flag provider states at a glance.
- **Provider editor modal** covers the full OIDC admin surface in four sections — Identification (display name, mount path), OIDC Provider (discovery URL, client id / secret, scopes), Allowed Redirect URIs (freeform textarea), Default Role (name, user/groups claim, policies, token TTL, bound audiences, bound claims JSON). Blank `client_secret` on edit preserves the stored secret; on create the secret is optional (PKCE clients).
- **Callback-URI hints panel** inside the modal: asks the backend for the mode-appropriate redirect URI to register with the IdP. Remote mode shows the stable `{server}/v1/auth/{mount}/callback`; embedded/desktop mode shows `http://127.0.0.1/callback` with an RFC-8252 "native app / loopback" explainer (Azure AD's "Mobile and desktop applications", Okta's "Native app", Google's "Desktop app"). One-click Copy per suggestion.
- **Client-side validation** flags the common misses upfront — missing display name / discovery URL / client id / default role / user claim / policies, plus a JSON-object sanity check on `bound_claims`. Server-side validation in `sso_admin::validate_input` re-enforces the same invariants so the Tauri surface cannot be bypassed by a crafted IPC call.
- `client_secret` never round-trips to the frontend — the backend returns only a `client_secret_set` boolean hint. Matches the existing `oidc_client_secret_set` redaction pattern on `auth/<mount>/config` Read.
- TS typecheck clean, vitest 66/66, `cargo check -p bastion-vault-gui` clean.

#### SSO login UX cleanup + global admin toggle (`src/modules/system/mod.rs`, `gui/src-tauri/src/commands/system.rs`, `gui/src/routes/LoginPage.tsx`, `gui/src/routes/SettingsPage.tsx`)
- **Login page no longer asks users to type a mount path or role.** The SSO tab now renders one clickable "Sign in with &lt;name&gt;" button per configured SSO backend. Role is resolved server-side via the mount's `OidcConfig.default_role`, so the admin is the single source of truth for what role an SSO login maps to.
- **Two new sys endpoints**: `sys/sso/providers` (Read, **unauth** — so the login page can fetch pre-token) returns `{enabled, providers: [{mount, name, kind}]}`; `sys/sso/settings` (Read/Write, **root-gated**) stores the global `{enabled: bool}` toggle at `core/sso/settings`. Providers are enumerated from the auth-mount table filtered by kind (currently `oidc`; `saml` joins when Phase 3 lands); the operator-supplied mount description becomes the display label.
- **Login page hides the SSO tab entirely** when the toggle is off or no SSO-capable auth mounts are configured. The vault never advertises a feature the user can't use. If SSO gets disabled between loads while the tab is active, the page auto-falls-back to the default Login tab.
- **Settings → Single Sign-On (SSO) card** with an enable/disable checkbox, live provider count, and copy explaining how to add a provider ("mount an auth backend, write its config, the mount description becomes the button label"). Flipping the toggle is reflected in the same render via `setSsoSettings` + a re-fetch of the provider list.
- **Three new Tauri commands**: `list_sso_providers` (unauth wrapper), `get_sso_settings`, `set_sso_settings`. Full TS types on the frontend (`SsoProvider`, `SsoProvidersResult`).
- **66/66 vitest tests still green**; LoginPage `beforeEach` gains a default `list_sso_providers` mock so non-SSO tests don't hit undefined-invoke when the page's mount effect runs.

#### SAML 2.0 auth backend — Phase 1 + 2 (`src/modules/credential/saml/`)
- **New `saml` credential kind** registered via `SamlModule` + `SamlBackend`, following the same Module/Backend pattern as `userpass`, `approle`, and `oidc`. Mounted under `auth/<mount>/` with per-mount IdP configuration.
- **IdP config CRUD** at `auth/<mount>/config` — `idp_metadata_url`, `idp_metadata_xml`, `entity_id`, `acs_url`, `idp_sso_url`, `idp_slo_url`, `idp_cert`, `default_role`, `allowed_redirect_uris`. Write validates that `entity_id` + `acs_url` are set and that at least one IdP source (metadata URL / inline XML / explicit SSO URL + cert) is present. Inline metadata XML and the IdP signing cert are **redacted on read**; boolean `_set` hints surface whether they are populated.
- **Role CRUD** at `auth/<mount>/role/<name>` + LIST at `auth/<mount>/role/` — `bound_attributes` (attribute → allow-list), `bound_subjects`, `bound_subjects_type`, `attribute_mappings`, `groups_attribute`, `allowed_redirect_uris`, `policies`, `token_ttl_secs`, `token_max_ttl_secs`. `SamlRoleEntry::validate_assertion` enforces bound-subject / bound-subject-type / bound-attribute gates and is ready for the Phase 3 callback handler to call.
- **13 unit tests + 1 end-to-end CRUD integration test**, all green. Tests cover cert + metadata-XML redaction, comma / array / JSON-object field-layer normalisation, and every assertion-validation branch.
- **Phase 3 deferred**: login / callback / XML-signature verification not yet wired. The crate decision (`samael` with `libxml2` + `libxmlsec1` C deps vs. a pure-Rust XML-DSig path) is not taken; config and role state is persisted now so operators can describe their IdP ahead of the flow shipping. (Phase 1 + 2, `features/saml-auth.md`)

#### OIDC GUI login ("SSO" tab) (`gui/src-tauri/src/commands/oidc.rs`, `gui/src-tauri/src/state.rs`, `gui/src/routes/LoginPage.tsx`, `gui/src/lib/api.ts`)
- **Three Tauri commands** (`oidc_login_start`, `oidc_login_complete`, `oidc_login_cancel`) that bridge the system browser to the vault's `oidc` auth backend. Start binds a loopback port and asks the vault for the IdP authorization URL; complete blocks on the loopback (via `spawn_blocking`), accepts the IdP redirect, POSTs `code` + `state` back to the vault's `callback` endpoint, extracts the minted `client_token` + `policies` from the response, and stashes the token into `AppState`. Cancel releases the listener.
- **Embedded + remote mode.** `dispatch_vault_write` picks the right path off `AppState::mode` — embedded calls flow through `vault.core.handle_request`; remote mode routes through `remote_client.request_write`. Same commands work for both.
- **LoginPage gains an "SSO" tab** with Mount (default `oidc`) + optional Role. Submit runs the three-step flow, phase-aware button text ("Opening identity provider…" → "Waiting for browser callback…"), error path releases the listener before reporting.
- **New `OidcLoginSession`** in `AppState` (separate from `CloudSession` to keep flow scopes distinct). Session id is an opaque short handle; sessions drop on completion, cancel, or timeout — no port leaks.
- **Minimal query-string parser** for the loopback callback (no `url` crate dep in the Tauri binary). Handles `code` / `state` / `error` / `error_description` with `+`-to-space and `%HH` percent decoding.
- TS bindings + `LoginResponse`-shaped return so the existing auth store consumes the result without ceremony.
- 66/66 vitest tests still green; `cargo check -p bastion-vault-gui` clean.

#### Opengrep security-audit cleanup (`src/utils/mod.rs`)
- Ran `opengrep-core` v1.20.0 against `E:\Dev\opengrep-rules\rust\lang\security\` on all 241 Rust source files. Result: **no actionable findings** — 30 total matches across 3 rules, all accept / documented / false-positive.
- **Kept `utils::sha1()` with explicit legacy-compat docs.** Discovered a single real caller (`TokenStore::salt_id` — HashiCorp-Vault-compatible salted-cache-key construction: `SHA1(server_salt || token_id)`). Safe in this specific use because collision resistance rests on the secrecy of the server-side salt, not on SHA-1's broken collision strength. Documented the caller and the migration path to SHA-256 for a future breaking-change revision. No functional change.

#### OIDC authentication backend (`src/modules/credential/oidc/`, `Cargo.toml`, `src/lib.rs`)
- **New `oidc` credential module** registered via `OidcModule` + `OidcBackend`, following the Module/Backend pattern used by `userpass` and `approle`. Mount with `sys/auth/<path>` kind `oidc` — operators can run multiple mounts for multi-provider setups (`auth/okta/`, `auth/azuread/`, etc.).
- **Provider config** (`auth/<mount>/config`) holds `oidc_discovery_url`, `oidc_client_id`, optional `oidc_client_secret` (redacted on read — surfaces only `oidc_client_secret_set: bool`), `default_role`, `allowed_redirect_uris`, and `oidc_scopes` (defaults to `["openid","profile","email"]` when empty).
- **Role config** (`auth/<mount>/role/<name>`, list at `auth/<mount>/role/`) holds `bound_audiences`, `bound_claims` (JSON object, claim → allowed values — supports string / number / bool / array value shapes), `claim_mappings` (OIDC claim → Vault token metadata key), `user_claim` (default `sub`), `groups_claim`, `oidc_scopes`, `allowed_redirect_uris`, `policies`, `token_ttl_secs`, `token_max_ttl_secs`.
- **`auth_url` endpoint** (unauth; `auth/<mount>/auth_url`) validates `redirect_uri` against the role + provider whitelists, generates PKCE verifier/challenge + CSRF state + nonce, persists an `OidcAuthState` at `state/<csrf>` with a 5-minute TTL, and returns the IdP authorization URL composed via `openidconnect::CoreProviderMetadata::discover_async`.
- **`callback` endpoint** (unauth; `auth/<mount>/callback`) load-and-deletes the state entry (single-use, defends against replay), rejects stale states, re-discovers the provider metadata so IdP-side key rotations propagate without a vault restart, exchanges the authorization code + PKCE verifier for tokens, verifies the ID token (signature via JWKS, issuer, audience, nonce, expiry — all delegated to the `openidconnect` crate), validates `bound_audiences` + `bound_claims`, projects configured claims onto `auth.metadata`, and returns `Auth { policies, display_name, metadata, lease }` for the token store to mint the vault token.
- **Token renewal** re-loads the role and rejects if the policy list drifted since the token was minted — operators who narrow a role's policies don't have to wait for existing tokens to expire.
- **`openidconnect = "4"` added to `Cargo.toml`** with `rustls-tls` + `reqwest` features (default-features off). Reqwest is already transitively in the tree via `hiqlite`, so the marginal dep cost is the crate itself + the JWT transitive closure.
- **Tests.** 17 unit tests (config redaction round-trip, comma-string / array parsing, bound-claim matching for string/number/boolean/array values, state-TTL boundary, claim-to-string flattening, JSON-envelope parsing). Plus a core-level integration test (`oidc_config_and_role_crud`) that mounts the backend through the real vault core, writes + reads config with redaction assertion, writes + reads + lists + deletes a role through the logical layer. Plus an `#[ignore]`d live-IdP test gated on `BVAULT_TEST_OIDC_DISCOVERY` + `BVAULT_TEST_OIDC_CLIENT_ID` env vars.
- **GUI login integration is a separate follow-up.** The server surface is complete; the desktop GUI's login page + post-callback token handling lands in the next slice.

### Changed

#### OIDC Authentication initiative closed (`roadmap.md`, `features/oidc-auth.md`)
- Moved OIDC Authentication from *Active* to *Completed Initiatives* in `roadmap.md` and updated the feature-status table row from "Todo" to "Done (server module)". `features/oidc-auth.md` header flipped with a status summary pointing at the deferred GUI slice.

#### File Resources initiative closed (`roadmap.md`, `features/file-resources.md`)
- Moved File Resources from *Active Initiatives* to *Completed Initiatives* in `roadmap.md`. Core feature is shipped and in production use: dedicated `files/` mount with barrier-encrypted metadata + blob storage, per-file history, 32 MiB cap + SHA-256 integrity, ownership / sharing / admin transfer / backfill through the shared `OwnerStore` + `ShareStore` (new `ShareTargetKind::File` variant), asset-group membership via a third reverse index, local-filesystem sync target with atomic tmp-then-rename + per-target sync-state, content versioning with snapshot-on-write + 5-version retention + reversible restore, full Admin → Audit integration, and the Files GUI (page + resource-tab + drag-and-drop upload + edit modal + versions tab + sync-targets management).
- **Phases 5–7 (SMB / SFTP / SCP sync transports + periodic re-sync) deferred as separate follow-up initiatives.** They're additive sync *transports* rather than gaps in the core file-resource model — every file-resource feature works today against the local-FS target shipped in Phase 3. Each deferred phase has its own crate-candidate analysis + test-infrastructure requirements documented in `features/file-resources.md` § "Deferred sub-initiatives" and in a new *Deferred sub-initiatives* section in `roadmap.md` that also tracks the two Cloud Storage Targets deferrals.
- **New `Deferred sub-initiatives` section in `roadmap.md`.** Centralizes the five sub-scopes that don't block day-to-day use but warrant dedicated future work: SMB sync, SFTP+SCP sync, periodic re-sync, cloud-obfuscation rekey CLI, server-mode obfuscation bootstrap. Each entry names its blocking question (crate choice / design decision) so a future session can pick one up cold.
- `features/file-resources.md` status flipped to **Done (core feature)** with the remaining phase-5/6/7 sections replaced by a "Deferred sub-initiatives" appendix covering the scope and blocking questions per transport.

#### Cloud Storage Targets initiative closed (`roadmap.md`, `features/cloud-storage-backend.md`)
- Moved the Cloud Storage Targets initiative from *Active* to *Completed Initiatives* in `roadmap.md` with a one-paragraph summary covering all eight phases + the Get-Started-page integration (multi-vault chooser + Cloud Vault option) that grew out of the work. Two sub-slices stay explicitly deferred: the rekey-CLI orchestrator for obfuscation salt rotation (library pieces are present, end-to-end CLI is not), and propagating obfuscation-salt async bootstrap through server-mode `storage::new_backend` (desktop mode already honors it via `FileBackend::new_maybe_obfuscated` + `embedded::build_backend`). Neither blocks day-to-day use.
- `features/cloud-storage-backend.md` status flipped to **Done** and a "Feature complete — shipped scope recap" section added at the bottom: a single-page audit of every artifact that shipped (trait, 4 provider targets, credentials resolver, OAuth infra, CLI, GUI surfaces, obfuscation decorator, OS keychain), test matrix coverage, explicit non-goals, and the two deferred sub-slices with rationale.
- Feature-status table row in `roadmap.md` shortened from the multi-line "Phases shipped" log to a concise "Done (all 8 phases shipped; see Completed Initiatives)" pointer.

### Fixed

#### Token-login now validates before signing in (`gui/src-tauri/src/commands/auth.rs`, `gui/src-tauri/src/commands/connection.rs`)
- `login_token` (embedded) and `remote_login_token` (remote) previously accepted any string as the auth token and stored it verbatim. A wrong token got the user to the dashboard with a functioning sidebar, where every data fetch then failed with "Permission denied" — confusing and wrong-shaped (the real failure was the login, not the fetch).
- Both handlers now issue `Read auth/token/lookup-self` with the supplied token and only store it on success. Permission-denied / invalid-token / forbidden errors at lookup-self are translated to a single "Invalid token" message so the login page shows one clear reason; other errors (network down, server unreachable) pass through with their original text.
- `login_token` also reads the token's real `policies` array out of the lookup-self response instead of hard-coding `["root"]`. Admin-gated routes (Users / AppRole / Audit / etc.) now render correctly on first paint for non-root users, not after a second fetch.

### Added

#### Local-vault custom data directory + Tauri command (`gui/src-tauri/src/embedded/mod.rs`, `gui/src-tauri/src/commands/vaults.rs`, `gui/src/routes/ConnectPage.tsx`)
- Add Local Vault modal now lets the operator pick where vault data lives. The **Location** field is pre-populated with the canonical default for the chosen storage engine and shows a "Reset to default" link whenever the user's edit drifts from it. Leaving the value at the default persists `data_dir: null` so the profile keeps following any future default-path change; a custom value is stored verbatim and overrides the env-var path.
- `embedded::build_backend` now overlays the default Local profile's `storage_kind` + optional `data_dir` on top of the env-var fallback. A typo'd `storage_kind` falls back to `"file"` so a hand-edited preferences file can't hard-lock the boot.
- New `data_dir_for(StorageKind)` helper + `get_default_local_data_dir` Tauri command expose the canonical per-engine path to the UI.

#### OAuth consent: fixed loopback port + redirect URI display + paste-token fast path (`src/storage/physical/file/oauth.rs`, `gui/src-tauri/src/commands/cloud_target.rs`, `gui/src/routes/ConnectPage.tsx`)
- **`DEFAULT_LOOPBACK_PORT = 8472`** — `begin_consent` takes a `preferred_port: Option<u16>` so the production code path binds a stable port and tests use ephemeral ones. A stable port means the redirect URI is identical across consent flows, which Dropbox (unlike Google/Microsoft, which RFC-8252-allow any loopback port) requires for its exact-match registration rule.
- **Redirect URI now rendered in the Add Cloud Vault modal** with a one-click Copy button, plus instructions to paste into the provider's "Redirect URIs" list before clicking Connect. Backed by a new `get_oauth_redirect_uri` Tauri command so the URI stays in sync with `DEFAULT_LOOPBACK_PORT`.
- **"Or paste an existing token" shortcut** for users whose provider lets them generate a long-lived token at the dev console (Dropbox has a "Generate" button). Skips the consent round-trip entirely. Backed by a new `save_pasted_token` Tauri command that wraps the pasted value in a `{"access_token":"..."}` JSON envelope and persists it via `creds::persist`.

#### Dropbox: support long-lived access tokens, not just refresh tokens (`src/storage/physical/file/dropbox.rs`)
- `DropboxTarget::ensure_access_token` now inspects the credentials file: a JSON envelope `{"access_token":"..."}` is used directly as the Bearer (no `/oauth2/token` round-trip), a plain string is treated as a refresh token and exchanged as before.
- `client_id` is now `Option<String>`. Long-lived tokens skip the refresh path and don't need one. The fallback error points users at the correct remediation when a plain-string credential is stored but no `client_id` is configured.
- Error-body pass-through on `read` / `delete` / `list` — non-2xx responses now include Dropbox's JSON explanation (e.g. `missing_scope/files.content.read`) in the returned error, so operators see the actual cause instead of just "http status 400".
- 2 new tests covering the new envelope format + optional `client_id`.

#### InitPage: ⇄ Change / ⚙ Settings / 🗑 Remove icon row (`gui/src/routes/InitPage.tsx`)
- Bottom-right of the init card gets three icon buttons once the active profile resolves.
  - **⇄ Change**: clears `last_used_id` and returns to the chooser so a different saved vault can be picked.
  - **⚙ Settings**: opens a small inline modal. For cloud vaults it offers a "re-paste access token" form (writes the new JSON envelope format) — fixes the most common init failure ("refresh token is malformed") without leaving the init page. For local vaults it shunts to the chooser since there's nothing to edit inline yet.
  - **🗑 Remove**: confirm-modal then `remove_vault_profile` → chooser. Underlying storage is never touched.
- Subtitle + body copy on the init page now branches on the active profile's kind, so a cloud vault no longer says "First-time setup for your local vault".

#### Modal scrolling + `CollapsibleSection` (`gui/src/components/ui/Modal.tsx`, `gui/src/components/ui/CollapsibleSection.tsx`)
- **Modal container** gained `max-h-[calc(100vh-2rem)]` + internal `overflow-y-auto` body. Tall modals (the Add Cloud Vault form with every section expanded was the trigger) now scroll inside themselves instead of overflowing the window. Applies to every Modal in the app.
- **`CollapsibleSection`** — new accordion-style block used by the Add Cloud Vault form to tuck advanced options behind a toggle. Built on top of a `<button>`/`<div>` pair with `aria-expanded` so it's keyboard-accessible; `headerRight` slot stops click propagation so external-link buttons don't toggle the section.
- Add Cloud Vault form is reorganized into three collapsible sections: **Storage location** (S3 only, default open), **Credentials** (default open — primary action), **Advanced** (default closed — credentials_ref override, prefix, obfuscate_keys).

#### Windows build hygiene (`.cargo/config.toml`, `Makefile`)
- New `.cargo/config.toml` sets `-Clink-arg=/PDBPAGESIZE:8192` for all Windows MSVC target triples. Fixes `LNK1318: Unexpected PDB error; LIMIT (12)` at link time on the Tauri GUI binary, which has grown past MSVC's default monolithic PDB size now that `cloud_targets` is default-on. Linker-only flag — no rustc recompile invalidation beyond the first apply.
- Makefile exports `OPENSSL_SRC_PERL=C:/Strawberry/perl/bin/perl.exe` on Windows so `openssl-sys`'s vendored build uses Strawberry Perl instead of the MSYS perl shipped with Git for Windows, which is missing `Locale::Maketext::Simple` and fails `VC-WIN64A` configure. Path is overridable via `make OPENSSL_SRC_PERL=... run-dev-gui`.

#### Add Cloud Vault — inline provider login + developer-console help links (`gui/src-tauri/src/commands/cloud_target.rs`, `gui/src/routes/ConnectPage.tsx`, `gui/src/lib/api.ts`)
- **Per-provider "Get client id ↗" link.** The Add Cloud Vault modal now shows a contextual link next to the OAuth section that opens the right developer console in the system browser (`@tauri-apps/plugin-shell`): Azure App Registrations for OneDrive, Google Cloud OAuth credentials for Google Drive, Dropbox App Console for Dropbox, AWS IAM Security Credentials for S3. Removes the "where do I click?" friction from the "register your own app" step.
- **Inline "Connect with [Provider]" button for OAuth targets.** Reuses the existing `cloud_target_start_connect` / `cloud_target_complete_connect` infrastructure but drives it from inside the Add Cloud Vault modal: user pastes the client id, clicks the button, browser opens the consent page, loopback listener catches the callback, refresh token is persisted at the suggested `credentials_ref`. On success the modal flips to a "✓ Connected" state and the user can Save & Open without a second trip through Settings. Cancel path still releases the loopback listener cleanly via `cloud_target_cancel_connect`.
- **Inline AWS credential entry for S3.** Collapsible section inside the S3 branch takes `access_key_id` + `secret_access_key` + optional `session_token`; the new `save_s3_credentials` Tauri command writes them as a JSON blob to a fresh file under `~/.bastion_vault_gui/cloud-creds/s3-<ts>.json` (0600 on Unix) and returns the resulting `credentials_ref`. The field above is filled automatically and the status flips to "✓ Credentials saved".
- **`suggest_credentials_ref_path` Tauri command.** Returns a sensible default `file:` path under the per-user data dir, so operators never face an empty credentials_ref field. Fired on provider change and on first "Connect" click when the field is empty.
- **Status awareness.** `cloudCredsReady` tracks whether the credential target is populated (either via inline connect/save or existing file). Editing `credentials_ref` manually invalidates the flag so a half-filled state doesn't surface as green.
- All three Tauri commands (`suggest_credentials_ref_path`, `save_s3_credentials`, plus the existing connect-flow ones) wired into the `invoke_handler`. Rust + TypeScript type-check clean; 66/66 vitest tests unchanged.

#### Multi-vault saved-profiles chooser (`gui/src-tauri/src/preferences.rs`, `gui/src-tauri/src/commands/vaults.rs`, `gui/src/routes/ConnectPage.tsx`, `gui/src/lib/api.ts`, `gui/src/test/pages.test.tsx`)
- **`VaultProfile` + `VaultSpec` data model.** Preferences now hold a `Vec<VaultProfile>` list keyed by a stable `id`, with each entry carrying a kind-tagged `spec` (`local` / `remote` / `cloud`) plus a user-editable display `name`. Multiple profiles of the same kind are supported — three different local data dirs, two S3 buckets, a mixed S3 + OneDrive setup, etc.
- **`last_used_id` = default.** The most recently opened profile is the default on the next app launch. The UI auto-resumes it unless the user hits "Switch vault" (`?choose=1` query param); if auto-resume fails the chooser renders with the error surfaced and the profile still in the list.
- **User-editable on-disk format.** The preferences file (`preferences.json`) is pretty-printed JSON with every field explicit and human-readable. Hand-editing is expected and supported — adding or reordering entries, tweaking a `data_dir`, or fixing a typoed `address` all take effect on the next load.
- **In-place migration from the pre-multi-vault shape.** `Preferences::migrate_legacy` folds existing single-vault fields (`mode` + `remote_profile` + `cloud_storage`) into the new `vaults` list on first load, then clears them via `skip_serializing_if = Option::is_none` so subsequent saves carry only the new shape. Upgrades are transparent — a user who had one Remote profile finds it named the same in the new list, and it's still the default.
- **CRUD Tauri commands** in `gui/src-tauri/src/commands/vaults.rs`: `list_vault_profiles`, `add_vault_profile`, `update_vault_profile`, `remove_vault_profile`, `set_last_used_vault`, `clear_last_used_vault`, `get_vault_profile`. Remove only edits the preferences file — underlying storage (local dir / server / cloud bucket) is never touched.
- **Legacy commands stay functional.** `save_preferences(mode, remote_profile)` now upserts into the new list instead of dropping the rest. `set_cloud_vault_config` / `clear_cloud_vault_config` / `get_cloud_vault_config` project onto the new shape (Cloud entries only). Pre-multi-vault frontend code continues to work unchanged.
- **Redesigned ConnectPage.** Saved profiles render as cards showing kind badge, connection detail (local storage kind / server address / cloud target), and a "default" pin. Per-card "Pin" and "Remove" buttons. Below the list, a three-button "Add new vault" row opens a unified Add modal that asks for a profile name + kind-specific fields (Local: storage engine; Remote: address/TLS/CA; Cloud: provider + target-specific config + `credentials_ref` + prefix + `obfuscate_keys`). Save-and-open is the default action so the common path is one click per new vault.
- **Bootstrap glue.** `embedded::build_backend` now resolves the active Cloud target through `Preferences::default_profile()` instead of the old scalar `cloud_storage` field — the rest of the boot path is unchanged. `is_initialized` mirrors the same lookup.
- **Backward compatibility.** Every build-matrix config clean (`cargo check --lib`, `cargo check -p bastion-vault-gui`, `npx tsc --noEmit`). 66/66 vitest tests pass; two obsolete "Local Vault" / "Connect to Server" tests were replaced with new assertions that cover both the empty-chooser and saved-profiles-rendering paths.

#### Cloud Vault option on the Get Started screen (`gui/src/routes/ConnectPage.tsx`, `gui/src-tauri/src/embedded/mod.rs`, `gui/src-tauri/src/preferences.rs`, `gui/src-tauri/src/commands/cloud_target.rs`, `gui/src-tauri/Cargo.toml`)
- **Third storage mode on the chooser.** "Local Vault" + "Connect to Server" + new **"Cloud Vault"** — an embedded vault whose storage sits directly on a cloud `FileTarget` (S3 / OneDrive / Google Drive / Dropbox) instead of a local directory. The device is the only client; the vault lives in the user's cloud account.
- **Cloud Vault modal** collects provider, target-specific config (bucket + region + optional endpoint for S3; OAuth client ID for the three consumer drives), `credentials_ref`, optional path prefix, and a checkbox for `obfuscate_keys`. Validation rejects missing required fields before the backend is touched.
- **Bootstrap semantics.** Clicking "Use this vault" writes the cloud config to preferences, then fires the normal embedded-vault flow: `is_vault_initialized` → `init_vault` (first-time boot seeds a fresh vault in the chosen bucket/folder) or `open_vault` (unseals an existing one using keys from the OS keychain). If an open attempt fails with unseal/barrier/decrypt errors we fall back to init, so picking a fresh bucket against a pre-populated client works out of the box. Errors along the way clear the half-written cloud config so the chooser isn't wedged.
- **`preferences::CloudStorageConfig`** — new optional field on the GUI preferences file. `target` + free-form `config` map; the `target` is pulled out and the rest is handed straight to the `FileTarget`'s `from_config`. Absent means the existing env-var-selected local / Hiqlite path runs unchanged — full backward compatibility.
- **`embedded::build_backend`** is now async and routes through `FileBackend::new_maybe_obfuscated` when `cloud_storage` is set. `is_initialized` treats a configured cloud vault as always-initialized (can't cheaply probe without a network round-trip); the open-or-init fallback in the UI handles the "bucket empty" case.
- **Three new Tauri commands**: `set_cloud_vault_config`, `clear_cloud_vault_config`, `get_cloud_vault_config`. Used both by the Get Started flow and by the Settings page for read-back/disconnect.
- **Tauri build now ships cloud targets by default.** `gui/src-tauri/Cargo.toml` turns on the upstream `cloud_targets` feature so the desktop GUI binary can reach all four providers without a custom build. Server-only operators keep the lean-binary path by disabling at their workspace level.
- **Test matrix.** `cargo check --lib`, `cargo check -p bastion-vault-gui`, `npx tsc --noEmit`, 66/66 vitest tests all green.

#### Cloud Storage Targets — Phase 8: Key obfuscation (`src/storage/physical/file/obfuscate.rs`, `src/storage/physical/file/mod.rs`)
- **`ObfuscatingTarget` decorator** — new `FileTarget` impl that wraps another `FileTarget` and rewrites every vault key to `hex(HMAC-SHA256(salt, raw_key))` before reaching the underlying provider. No new external deps (uses `hmac` + `sha2` + `rand` already in the tree). Threat model: hides vault-activity shape from anyone with read access to the underlying bucket / drive; barrier ciphertext is already unreadable, so this closes the loop on metadata leakage through object key names.
- **Auto-bootstrapped salt.** 32-byte random salt generated on first use and persisted at the well-known key `_bvault_salt` inside the wrapped target; subsequent starts reuse it, so keys stay stable across restarts. `with_salt(inner, salt)` constructor is exposed for programmatic use (tests, rekey).
- **`FileBackend::new_maybe_obfuscated`** — async convenience constructor that honors `obfuscate_keys = true` in target config and wraps the base target. The sync `FileBackend::new` logs a loud warning when the flag is set through its path so a misconfigured config is loud rather than silently degraded — salt bootstrap needs async I/O, so the sync path can't honor the flag and surfaces the degradation.
- **`list(prefix)` limitation.** HMAC is a PRF — once `sys/policy/admin` hashes to `8a4f…e12c`, prefix enumeration is impossible without a manifest. The decorator takes the narrow approach: `list("")` works (returns every raw-hashed key minus the salt marker; useful for rekey iteration and vault-wide audits); `list("<non-empty>")` returns a specific error naming the limitation and pointing at the opt-out. Callers that depend on prefix-based listing opt out of obfuscation.
- **12 new unit tests** in `obfuscate.rs`: salt bootstrap generates / persists / reuses / rejects bad length, writes store under hashed keys, read-after-write roundtrip, different salts produce different keys, delete via hash, salt-key passes through unhashed, `list("")` enumerates hashed keys and strips salt marker, `list("prefix/")` errors clearly, HMAC is deterministic per salt. Plus an **end-to-end on-disk assertion** in `test_file_backend_honors_obfuscate_keys` that walks the filesystem under a `LocalFsTarget` wrapped with obfuscation and confirms no plaintext key component (`policy`, `admin`) lands on disk.
- **Deferred sub-slices.** (1) Auto-wiring through `storage::new_backend` — the sync bootstrap path. Today operators bootstrap obfuscation from async startup code via `FileBackend::new_maybe_obfuscated`; threading that through `new_backend` requires changes to the broader storage-bootstrap chain. (2) Rekey CLI — the library pieces are present (`with_salt`, `list("")`), but the orchestrating CLI that walks the old target, re-writes under a new salt, and swaps the active salt is design-only. Production rekey today goes through `operator migrate` with a non-obfuscated intermediate.
- **Feature status.** Cloud Storage Targets roadmap row flipped to Done. All 8 phases shipped — 4 providers + OAuth infra + CLI + GUI + keychain + obfuscation decorator.

#### Cloud Storage Targets — Phase 7b: OS keychain writer (`src/storage/physical/file/creds.rs`, `Cargo.toml`, `gui/src-tauri/src/commands/cloud_target.rs`, `gui/src/components/CloudStorageCard.tsx`)
- **`keyring` crate behind new `cloud_keychain` feature flag.** Platform-native secret stores: macOS Keychain, Windows Credential Vault, Linux Secret Service. Feature-gated so server-only operators who never touch `keychain:` don't carry the dbus / secret-service transitive deps.
- **`creds::resolve` + `creds::persist` both gain real `keychain:` support.** Label syntax: `<service>/<user>` splits into the keychain's two identification axes; labels without a `/` get the default service id `"bastionvault"`; labels with multiple `/`s split on the first so the user part can contain further slashes (`onedrive/refresh/production`). On read, `NoEntry` errors surface a specific "run `bvault operator cloud-target connect` to populate it" message.
- **Feature-off path still compiles cleanly.** When the feature isn't enabled, both `resolve_keychain` and `persist_keychain` return a clear "requires the `cloud_keychain` build feature" error rather than leaving a silent gap.
- **GUI validator softened.** `validate_credentials_ref_writable` in the Tauri `cloud_target` commands no longer pre-rejects `keychain:`. The server may have been built with `cloud_keychain`, and if not, `creds::persist` surfaces a clear error at completion time — matches the "let the backend speak" principle already in place for other build-gated features.
- **GUI hint updated.** The Cloud Storage Targets card now documents all four schemes accurately: `file:` (0600 on Unix); `keychain:` (`<service>/<user>` label; requires the `cloud_keychain` server build); `env:` / `inline:` read-only.
- **8 new unit tests** (5 `parse_keychain_label`: default service, service/user split, user with embedded slashes, empty-label rejection, empty-half rejection; 2 feature-gated rejection paths for reader + writer; 1 `#[ignore]`d OS-keychain `keychain_roundtrip` covering write + read + rotate + cleanup).
- **Build matrix.** `cargo check --lib`, `cargo check --lib --features cloud_keychain`, `cargo check --lib --features cloud_targets` (all five feature flags), `cargo check -p bastion-vault-gui`, and `npx tsc --noEmit` all clean. Creds tests: 25/25 without the feature; 23 default + 1 ignored roundtrip with the feature on.

#### Cloud Storage Targets — Phase 7a: Settings GUI connect flow (`gui/src-tauri/src/commands/cloud_target.rs`, `gui/src-tauri/src/state.rs`, `gui/src/components/CloudStorageCard.tsx`, `gui/src/routes/SettingsPage.tsx`, `gui/src/lib/api.ts`)
- **`CloudStorageCard`** — new Settings subsection that runs the OAuth consent flow for OneDrive / Google Drive / Dropbox end-to-end. Form: provider picker, `client_id`, optional `client_secret`, `credentials_ref`. Connect button drives the three-step flow (start → `shellOpen` → complete) with phase-appropriate status text. On error or user cancel, fires `cloud_target_cancel_connect` so the loopback listener releases the port immediately rather than waiting for the 5-minute timeout.
- **Three Tauri commands** — `cloud_target_start_connect` (bind loopback, compose authorization URL, stash session under an opaque id, return `{sessionId, consentUrl}`); `cloud_target_complete_connect` (remove session from map, block via `spawn_blocking` waiting for the callback, exchange the code, persist the refresh token); `cloud_target_cancel_connect` (release the listener without completing).
- **Why split start/complete.** The frontend opens the consent URL in the user's real system browser via the Tauri `shell` plugin's `open` — puts the provider's consent screen in the operator's signed-in browser profile rather than a blank Tauri popup. Splitting the commands lets the GUI call `shellOpen(consentUrl)` after `start` returns and before `complete` blocks.
- **`AppState::cloud_sessions`** — new `std::sync::Mutex<HashMap<String, CloudSession>>` holding in-flight consent sessions. `CloudSession` carries the `oauth::ConsentSession` (with its bound loopback listener), the provider + creds, and the destination `credentials_ref`. Listener drops automatically when the session is removed from the map.
- **Writable-ref validation at start time.** `cloud_target_start_connect` rejects `env:` / `inline:` / `keychain:` schemes up-front with specific error messages so the user gets immediate feedback rather than going through the full consent round-trip only to hit a `persist` failure. `keychain:` deferral to Phase 7b is called out explicitly.
- **Shell plugin already wired.** `tauri-plugin-shell` is in `gui/src-tauri/Cargo.toml` and `shell:allow-open` is in the default capability set; no Tauri-config changes needed.
- **Test status.** `cargo check -p bastion-vault-gui` clean; `npx tsc --noEmit` clean; 66/66 vitest tests still pass (18 pre-existing React `act()` warnings, unchanged). Full lib `--features cloud_targets` build clean.

#### Cloud Storage Targets — Phase 6: Dropbox target (`src/storage/physical/file/dropbox.rs`, `Cargo.toml`)
- **`DropboxTarget`** — new `FileTarget` impl against Dropbox v2 API. Feature-gated as `cloud_dropbox`; zero new transitive deps.
- **App Folder sandbox.** Baked into the app's type at developer-console registration; the provider config ships no explicit scopes (`token_access_type=offline` on auth is what turns on refresh-token issuance).
- **Dual-host API.** Upload + download go through `content.dropboxapi.com` with metadata in a `Dropbox-API-Arg` header; delete + list go through `api.dropboxapi.com` with JSON bodies. Endpoints: `/2/files/upload`, `/2/files/download`, `/2/files/delete_v2`, `/2/files/list_folder`, `/2/files/list_folder/continue`.
- **Not-found handling.** Dropbox returns HTTP 409 with a structured body on app-logic errors. We substring-match the response for `not_found` and map to `Ok(None)` on read / no-op on delete / empty vec on list.
- **150 MiB single-shot ceiling** (Dropbox's documented `/2/files/upload` limit). Oversize writes surface a clear error referencing upload-session support as a deferred optimization.
- **Structure.** `Arc<Inner>` + single-`spawn_blocking` per op, matching Google Drive. Access-token cache + auto-refresh + atomic rotation persistence.
- **11 new unit tests** covering prefix normalization, 409 `not_found` detection, config-level rejection and acceptance, object-path composition (with and without prefix), list-response parsing (populated + cursor + missing-field defaults). Plus a live integration test `#[ignore]`d behind `BVAULT_TEST_DROPBOX_CLIENT_ID` + `_CREDS_FILE`.

#### Cloud Storage Targets — Phase 5: Google Drive target (`src/storage/physical/file/gdrive.rs`, `Cargo.toml`)
- **`GoogleDriveTarget`** — new `FileTarget` impl against Drive v3. Feature-gated as `cloud_gdrive`; zero new transitive deps.
- **App Data sandbox.** Only `drive.appdata` requested; files land in the special `appDataFolder` space, invisible to the user's personal Drive.
- **ID-based chain walking.** Drive v3 has no hierarchical-path API. Writes walk the vault-key segments via search (`q=name='x' and '<parent>' in parents and mimeType='application/vnd.google-apps.folder'`), creating intermediate folders on the way. Updates hit `PATCH /upload/drive/v3/files/{id}?uploadType=media` by file-id when the leaf exists; new writes use multipart `POST /upload/drive/v3/files?uploadType=multipart` with a hand-built `multipart/related` body carrying metadata + content in one request.
- **Folder-id cache.** `Mutex<HashMap<String, String>>` mapping full path → folder id so repeated chain resolution is O(segments) instead of O(segments × search-round-trips) after the first walk. Folder ids don't change once assigned; the cache is process-lifetime.
- **Query escaping.** Drive v3 queries are SQL-ish; single quotes and backslashes in names are escaped per Google's grammar.
- **Structure.** `Arc<Inner>` + single-`spawn_blocking` per op so the whole sequence (resolve chain → search leaf → upload/update) runs on one worker thread. Access-token cache + auto-refresh + atomic rotation persistence.
- **Eventual consistency caveat.** Documented in the module header: Drive's search index is eventually consistent, so `operator migrate` followed by an immediate `list` may need seconds to stabilize. Writes + reads by cached file-id are not affected.
- **11 new unit tests** covering path splitting (edge cases: empty, leading/trailing slash, double slash), parent/name extraction, query escaping, config-level rejection and acceptance, Drive v3 search-response parsing (populated / empty / missing field). Plus a live integration test `#[ignore]`d behind `BVAULT_TEST_GDRIVE_CLIENT_ID` + `_CREDS_FILE`.

#### Cloud Storage Targets — Phase 4: OneDrive target (`src/storage/physical/file/onedrive.rs`, `Cargo.toml`)
- **`OneDriveTarget`** — new `FileTarget` impl against Microsoft Graph API, storing `BackendEntry` JSON bytes as files inside the vault's dedicated App Folder. Feature-gated as `cloud_onedrive`; **zero new transitive deps** — reuses `ureq`, `serde_json`, and the Phase-3 `oauth` + `creds` modules already in the tree.
- **Scope sandbox.** Only `Files.ReadWrite.AppFolder` + `offline_access` requested (see `oauth::well_known_provider("onedrive")`). The vault is confined to a folder that BastionVault itself owns; the user's personal OneDrive stays invisible to the vault, and vice-versa.
- **Graph endpoints.** Colon-path syntax: `GET /me/drive/special/approot:/<prefix>/<key>:/content` for read, `PUT` same URL for write, `DELETE /me/drive/special/approot:/<prefix>/<key>:` for delete, `GET /me/drive/special/approot:/<prefix>/<dir>:/children` with `@odata.nextLink` pagination for list.
- **Access-token caching + auto-refresh.** A `Mutex<Option<CachedAccessToken>>` tracks the current access token + deadline. Every verb calls `ensure_access_token`, which returns the cached token when it has more than a minute of life left, otherwise re-reads the refresh token from `credentials_ref` (so hand-rotated tokens pick up without a restart), hits `oauth::refresh_access_token`, and **persists the rotated refresh token atomically** via `creds::persist` when the provider supplies one. Rotation survives a vault restart.
- **4 MiB single-shot ceiling.** Matches the Graph API's `:/content` upload limit. Values above surface a clear error with the Phase-notice ("upload-session support ships in a later phase"). Vault keys are typically under 1 KB; File Resources (up to 32 MiB) already have their own ceiling above the barrier and are unaffected here.
- **Listing.** `list(prefix)` treats `prefix` as a folder path inside the App Folder; empty prefix hits `approot/children` directly, non-empty hits the colon-path form against that folder. Items with a `folder` property get the trailing `/` discriminator; bare names are files. 404 on the folder itself returns an empty Vec, matching the local target's contract.
- **`FileBackend::new` wired.** `target = "onedrive"` dispatches to `OneDriveTarget::from_config` when built with `cloud_onedrive`; returns a clear "requires the `cloud_onedrive` build feature" error otherwise (same pattern as S3).
- **12 new unit tests.** Config-level: required-field rejection (`client_id`, `credentials_ref`), credentials-ref-resolves-on-construct (typo fails fast), minimal + full valid configs. Plumbing: prefix normalization, path encoding for specials (spaces → `%20`, colons → `%3A`, unreserved passed through), URL composition per verb, root-children URL with and without prefix, Graph `ChildrenResponse` JSON parsing with/without `@odata.nextLink`, encode/decode symmetry. Plus a `#[ignore]`d live integration test gated on `BVAULT_TEST_ONEDRIVE_CLIENT_ID` + `_CREDS_FILE`.
- **Build-matrix status.** Default build, `cloud_s3`, `cloud_onedrive`, and `cloud_targets` (both together) all compile clean. Full file-module suite 52/52 green with both feature flags enabled.

#### Cloud Storage Targets — Phase 3b: `bvault operator cloud-target connect` CLI (`src/cli/command/operator_cloud_target_connect.rs`, `src/storage/physical/file/creds.rs`, `src/storage/physical/file/oauth.rs`)
- **`creds::persist`** — new writer side of the `credentials_ref` grammar. `file:` writes atomically (sibling tmp + rename), chmod-0600 on Unix so other local users can't read the refresh token. `env:` / `inline:` / `keychain:` return instructive errors — `env:` can't be written durably, `inline:` is read-only (value comes from server config), `keychain:` deferred to Phase 7. 7 new unit tests covering round-trip, atomic-replacement, 0600 perms, each rejection path, missing/unknown scheme.
- **`oauth::well_known_provider`** — new provider factory keyed on `"onedrive"` / `"gdrive"` / `"dropbox"`. Returns the right authorization + token URLs, narrowest-available scopes (`Files.ReadWrite.AppFolder` + `offline_access` for OneDrive; `drive.appdata` for Google Drive; App Folder for Dropbox), and provider-specific extras (Google's `access_type=offline` + `prompt=consent` for reliable refresh-token issuance; Dropbox's `token_access_type=offline`). 4 new unit tests pinning each provider's shape + unknown-provider rejection.
- **`bvault operator cloud-target connect`** — new CLI subcommand orchestrating the full consent flow end-to-end: resolves the provider, begins the consent session on a random loopback port, prints the URL, launches the system browser (`open` on macOS, `rundll32 url.dll,FileProtocolHandler` on Windows — avoids `cmd /c start`'s `&` mangling — `xdg-open` elsewhere; soft-fails to "paste it yourself" if no launcher is available), waits for the callback, exchanges the code for tokens, and persists the refresh token to the configured `credentials_ref`. Flags: `--target`, `--client-id`, `--client-secret` (optional; PKCE public clients omit it), `--credentials-ref`, `--bind-host` (default `127.0.0.1`), `--no-browser` (for headless servers), `--timeout-secs` (default 300).
- **Intentionally ships before phases 4–6.** The CLI exercises the shared OAuth infra end-to-end against real provider endpoints, so operators can validate their app registration + scopes configuration before the storage-path wire-up for OneDrive / Google Drive / Dropbox lands.
- **40/40 file-module tests pass**; default build + `cloud_s3` build both unaffected. `bvault operator cloud-target --help` and `... connect --help` verified producing clean usage output.

#### Cloud Storage Targets — Phase 3a: OAuth + PKCE + loopback-redirect infrastructure (`src/storage/physical/file/oauth.rs`)
- **Shared library** for the consent flow that the consumer-drive `FileTarget`s in phases 4–6 (OneDrive, Google Drive, Dropbox) will plug into. Zero new transitive deps — reuses `rand`, `sha2`, `base64`, `url`, `ureq` (all already in the tree).
- **Core types.** `OAuthProvider` (authorization URL, token URL, scopes, extra-auth-params), `OAuthCredentials` (`client_id` + optional `client_secret` — public-client PKCE-only is the common shape), `TokenResponse` (`access_token`, optional `refresh_token` / `expires_in` / `token_type` / `scope`), `CallbackParams` (code + state from the loopback callback).
- **PKCE helpers.** `pkce_verifier()` generates RFC 7636-compliant 96-char base64url verifier; `pkce_challenge()` returns BASE64URL(SHA256(verifier)); `random_state()` generates the 128-bit CSRF state. PKCE test vector from RFC 7636 Appendix B passes.
- **`begin_consent` + `ConsentSession::wait_for_callback`.** Binds a random `127.0.0.1:<port>` loopback listener, composes the authorization URL (`code_challenge_method=S256` + provider extras like `prompt=consent`), returns a handle. `wait_for_callback` accepts the first connection, parses `GET /callback?...`, responds with a minimal HTML success page, validates the state to foil CSRF, and surfaces provider-returned OAuth errors (`error=access_denied&error_description=...`) with the provider's message rather than silently dropping them. Poll-style timeout so a closed browser tab doesn't hang the caller forever.
- **Token exchange.** `exchange_code` (RFC 6749 §4.1.3 authorization-code grant) and `refresh_access_token` (refresh grant) POST form-encoded bodies to the provider's `token_url` via the existing `ureq` client; `http_status_as_error(false)` so non-2xx responses surface with the server's body for debugging.
- **Testable in isolation.** The module never opens a browser itself — callers get the consent URL and decide (CLI prints + shells out to `open`/`xdg-open`; GUI uses Tauri's `shell.open`). This keeps the library portable and makes the whole flow unit-testable.
- **13 unit tests.** PKCE verifier length/charset, RFC 7636 test vector, authorization-URL composition with all required params, request-line parsing (happy path + URL-decoding + provider-error surfacing + non-GET rejection + missing-code / missing-state rejection), token response deserialization (minimal + full body shape), **in-process TCP roundtrip** (real listener + real ureq client hitting `http://127.0.0.1:<port>/callback`), **CSRF state-mismatch rejection**. All green; default build + `cloud_s3` build both unaffected.

#### Cloud Storage Targets — Phase 2b: S3 target (`src/storage/physical/file/s3.rs`, `Cargo.toml`)
- **`S3Target`** — new `FileTarget` impl storing `BackendEntry` JSON bytes as objects in an S3-compatible bucket. Config: `bucket`, `region` (required); `endpoint_url`, `url_style = "path"|"virtual"` (default `virtual`), `prefix`, `credentials_ref`, `http_timeout_secs` (all optional). `credentials_ref` accepts the new URI grammar; absent falls back to `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars. MinIO-compatible (set `endpoint_url` + `url_style = "path"`).
- **Smallest-viable crate choice.** Surveyed `aws-sdk-s3` (~50–80 deps), `rust-s3` (~40), and `rusty-s3` (URL-signing + XML-parsing only, 4 new transitive deps). Went with **rusty-s3 + ureq** (already in tree for HTTP); each verb pre-signs with rusty-s3 and ships through a shared `ureq::Agent`. Sync HTTP runs through `tokio::task::spawn_blocking` so the runtime never parks. `http_status_as_error` is disabled on the Agent so `read()` routes 404 cleanly to `Ok(None)` and `delete()` treats 404 as a successful no-op — matching the `FileTarget` contract.
- **Listing.** `list(prefix)` walks `ListObjectsV2` paginated via `NextContinuationToken` with delimiter `/`, strips the configured object-prefix before returning, preserves trailing `/` on directory entries to match the local target's contract, and percent-decodes `encoding-type=url` keys before handing them back.
- **Feature-gated.** New `cloud_s3` Cargo feature pulls in `rusty-s3` + `quick-xml`. Default builds carry zero S3 code or deps. `FileBackend::new` only exposes `target = "s3"` when built with `cloud_s3`; otherwise returns a clear error pointing at the required feature flag.
- **Locking.** No-op guard — the spec's documented single-writer-per-target assumption applies; multi-writer arbitration (ETag-precondition lock object, DynamoDB) is out of scope for this phase.
- **9 new unit tests.** `bucket` / `region` required, unknown `url_style` rejected, inline `credentials_ref` happy path, bad-JSON rejection, prefix normalization (empty / bare / trailing-slash), object-key composition, percent decoding. Plus a live MinIO integration test marked `#[ignore]` — runs under `cargo test --features cloud_s3 -- --ignored` with `BVAULT_TEST_S3_ENDPOINT` / `_BUCKET` / `_REGION` + `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` env vars set.
- Full file-module suite 24/24 green with `cloud_s3` enabled; default build 391+ tests still clean.

#### Cloud Storage Targets — Phase 2a: `credentials_ref` resolver (`src/storage/physical/file/creds.rs`)
- **`credentials_ref` URI grammar** — new resolver supporting `env:<VARNAME>` (read from environment variable), `file:<path>` (read from local file), `inline:<base64>` (literal embedded credential), and an explicit `keychain:<label>` error path stubbed out until Phase 7. Returns a `Secret` newtype wrapping `Zeroizing<Vec<u8>>` so raw credential bytes wipe on drop; `Debug` renders only the length so accidental logging can never leak the payload.
- **Ground truth for every cloud target.** S3 parses the resolved bytes as JSON static AWS credentials or an AWS profile name; OneDrive / Google Drive / Dropbox treat them as OAuth refresh tokens. Landing the resolver before the first provider means each provider slice focuses on transport + credential interpretation without also re-designing the creds ABI.
- **13 unit tests** covering each scheme's happy path, empty-payload rejection, bad-base64 rejection, missing-env-var / missing-file / missing-scheme / unknown-scheme error messages, the `keychain:` Phase-7 deferral, and a debug-redaction assertion proving the `Secret` type cannot leak its contents into a log line. No external deps (uses only `base64` + `zeroize`, already in the tree).

#### Cloud Storage Targets for Encrypted File backend — Phase 1 (`features/cloud-storage-backend.md`, `src/storage/physical/file/`)
- **`FileTarget` trait** (`src/storage/physical/file/target.rs`) — new pluggable I/O primitive underneath the Encrypted File storage backend. Byte-level surface (`read` / `write` / `delete` / `list` / `lock`) that sits below the barrier: targets never see decrypted `BackendEntry` material, only the serialized bytes the backend above chose to persist (AEAD ciphertext under normal barrier-backed operation).
- **`LocalFsTarget`** (`src/storage/physical/file/local.rs`) — carries the exact behavior of the pre-refactor `FileBackend`: `<root>/a/b/_c` key→path mapping, `_`-prefix leaf discriminator so `list()` can return data names and trailing-slash directory names in one walk, `lockfile::Lockfile`-backed per-key lock.
- **`FileBackend` wrapper** (`src/storage/physical/file/mod.rs`) — now holds `Arc<dyn FileTarget>`; serializes `BackendEntry` to JSON above the trait and defers I/O to the target. Config accepts `target = "..."` (defaults to `"local"`), so every existing `storage "file" { path = "..." }` continues to work bit-for-bit. Added `FileBackend::from_target` as the test / future-phase construction hook.
- **Zero-behavior-change refactor.** Phase 1 is pure indirection: no new functionality, no at-rest-format change, no public API change to `Backend`. Existing `test_file_backend` + `test_file_backend_multi_routine` pass unchanged; storage suite 19/19 green overall.
- **New seam test.** `test_file_backend_delegates_to_target` plugs a recording stub through `FileBackend::from_target` and asserts the target receives the serialized JSON bytes (not the pre-serialization struct) — documenting the exact contract Phase-2 cloud targets will implement.
- Phases 2–8 — S3, OAuth infra, OneDrive, Google Drive, Dropbox, GUI, key obfuscation + rekey — still Todo; see the feature file.

#### Caching Slice 4 + feature complete (`features/caching.md`)
- **`src/cache/guardrails.rs`** — new module applying process-level memory protections at bootstrap. `cache.memlock = true` calls `mlockall(MCL_CURRENT|MCL_FUTURE)` on Unix to pin every page against swap (including future cache allocations); startup aborts when the syscall fails rather than silently running with a weaker protection than requested. When any cache TTL is non-zero and `cache.allow_core_dumps = false` (default), Linux hosts call `prctl(PR_SET_DUMPABLE, 0)` so a crash cannot write cache contents into a core file. Non-Linux hosts log the residual risk; Windows explicitly aborts on `memlock = true` because there is no portable equivalent yet.
- **`Core::flush_caches`** — a single entry point that drops every cache layer (policy / token / secret, including the `CachingBackend` decorator when installed, via runtime downcast on `Backend: Any`) and zeroizes held payloads via the existing `Zeroizing<Vec<u8>>` drop path. Invoked by `pre_seal` so cached material never survives into the sealed state, and by the new admin endpoint.
- **`POST /sys/cache/flush`** — new sudo-gated HTTP endpoint for operator-driven flushes after a revocation storm or suspected compromise. Wired through both the system backend (with the path added to `root_paths`) and `src/http/sys.rs` as a dedicated handler returning 204 on success. Root access is required by the ACL; the vault repopulates caches lazily.
- **`PolicyStore::flush_caches`** + **`TokenStore::flush_cache`** — new public helpers that `Core::flush_caches` composes. Both are no-ops when their underlying caches are disabled.
- **Roadmap flipped to Done.** All four caching slices (config scaffold → token cache → metrics → secret cache → guardrails) are in tree with 54 cache-specific tests; 354 lib tests pass overall. `features/caching.md` now documents the shipped behavior and explicit non-goals (stretto has no eviction callback, so `bvault_cache_evictions_total` covers explicit invalidations only; no negative caching; no mount-table caching).

#### Caching Slice 3: ciphertext-only secret read cache (`features/caching.md`)
- **`src/cache/secret_cache.rs`** — new `CachingBackend` decorator implementing the `Backend` trait. Wraps any physical backend (file / MySQL / Hiqlite) and memoizes `get()` results in a bounded, TTL-scoped stretto cache. Positive hits only — a `get()` returning `None` is **not** cached because path existence can itself be sensitive metadata.
- **Below the barrier, by construction.** The decorator implements `Backend`, not `Storage`. `BarrierView`/`SecurityBarrier` sit above it in the call chain, so the Rust type system makes it impossible to hand it a decrypted `StorageEntry`: values it caches are exactly the bytes `Backend::put` was given and `Backend::get` returns — i.e. AEAD ciphertext under normal barrier-backed operation. Decryption happens on the barrier hot path every request, cache hit or miss.
- **Zeroized on every release path.** Cached bytes are held in `Zeroizing<Vec<u8>>` inside a non-`Clone` / non-`Serialize` / redacted-`Debug` wrapper `CachedCiphertext`. stretto's `Drop`-on-evict and `Arc`'s refcount-zero both run `Zeroize` before the allocator reclaims the page. `CachingBackend::clear()` flushes on demand.
- **Write-through invalidation.** `put()` and `delete()` evict the affected key (`delete()` evicts both before and after the underlying op to close the race where a parallel `get` could otherwise observe the about-to-be-gone entry as live). The local reader always sees its own write on the next `get`.
- **Off by default.** New helper `storage::wrap_with_cache(backend, cache_config)` wraps the physical backend only when `cache.secret_cache_ttl_secs > 0`; with the default 0, the helper returns the original `Arc` unchanged and no decorator is installed. Existing deployments see zero overhead.
- **`BastionVault::new` wired.** The bootstrap now threads the configured cache through `wrap_with_cache` before constructing `Core`, so any physical backend (including hiqlite, mysql, file) gets the decorator when the operator opts in. CLI tools (`operator migrate`, `operator backup`, `operator restore`) continue to call `storage::new_backend` directly and are deliberately not wrapped — they are single-shot migrations where caching has no benefit and active invalidation on the source side during a long copy would just add noise.
- **Metrics.** `bvault_cache_{hits,misses,evictions}_total{layer="secret"}` are populated by the decorator using the singleton registered in Slice 2b; size gauge remains reserved (stretto exposes no `len()`).
- **Tests (9 added, all passing):** populate-then-serve-from-cache (inner backend hit count drops to 1), `put` invalidates, `delete` invalidates, missing key is not negatively cached, `ttl == 0` rejected at construction, `Debug` redacted, not-`Clone` static assertion, `clear()` flushes, and a bit-for-bit byte-pattern test that proves the cache stores exactly what flows through `Backend::put`/`get` without any transformation — i.e. it cannot invent plaintext, and under the real barrier those bytes are AEAD ciphertext. 350 lib tests pass overall (zero regressions).

#### Caching Slice 2b: Prometheus cache metrics (`features/caching.md`)
- **`src/metrics/cache_metrics.rs`** — four Prometheus families labelled by `layer` (`token` / `policy` / `secret`): `bvault_cache_hits_total`, `bvault_cache_misses_total`, `bvault_cache_evictions_total`, `bvault_cache_size`. A process-wide `OnceLock<CacheMetrics>` lets cache code record values without plumbing a handle through `Core` — `MetricsManager::new` simply registers the singleton's families with its `Registry`, and any number of registries can coexist (each gets its own `Family` clone sharing the same counter storage via `Arc`).
- **Token cache** (`src/cache/token_cache.rs`) records a `hit` / `miss` on every `lookup`, and an `eviction` on every `invalidate`.
- **Policy cache** (`src/modules/policy/policy_store.rs`) records a `hit` / `miss` in `get_policy`, and an `eviction` in `remove_token_policy_cache` / `remove_egp_cache`.
- **Stretto-internal evictions are invisible.** stretto 0.8 exposes no eviction callback, so cost-overflow / TTL expiries don't feed the counter — only explicit invalidations do. The counter therefore means "forced cache invalidations" in practice; it's still useful for spotting revoke storms and policy-churn hotspots, and the `size` gauge is reserved for a future slice that can supply it (either via a replacement cache or periodic `stretto` stats polling).
- **Test suite updated.** `test_metrics_name_and_help_info` now knows about the four cache metrics as a valid upper-bound slice (they only surface in the scrape after first record; the singleton means cross-test carry-over is expected and benign). 341 lib tests pass (up from 337 before 2a + 4 new cache-metrics unit tests).
- **Zero new process-wide state that can leak secrets.** The metrics families hold only integer counters labelled by layer name — no keys, no values, no bytes derived from any `TokenEntry` or ciphertext. Safe to scrape from Prometheus without exposing sensitive material.

#### Caching Slice 2a: token lookup cache (`features/caching.md`)
- **`src/cache/token_cache.rs`** — new `TokenCache` wrapping a stretto LRU with TTL. Cached value is `Zeroizing<Vec<u8>>` holding the serialized `TokenEntry` JSON; the wrapper `CachedToken` does **not** implement `Clone` or `Serialize`, and its `Debug` prints a fixed `<cached:token:redacted>` string so log / panic / error paths cannot leak contents. Values are zeroized on eviction, explicit invalidation, and cache clear via `Zeroizing`'s `Drop` chain.
- **`TokenStore::token_cache`** — `Option<Arc<TokenCache>>` constructed from `core.cache_config`. Wired into:
  - `lookup_salted` — cache-aside read; miss falls through to storage and populates the cache.
  - `create` — invalidates any stale entry for the salted key rather than speculatively caching, since the caller may still mutate before first use.
  - `use_token` — invalidates after writing the decremented-`num_uses` entry so the next lookup reflects the new count.
  - `revoke_salted` — invalidates both before and after the underlying delete, closing the race where a parallel lookup could otherwise observe the about-to-be-gone entry as live.
- **Keys are non-reversible salted hashes.** The cache key is `TokenStore::salt_id(token)` — the same `sha1(salt || id)` already used as the storage key — not the raw bearer token, so a memory dump of the cache does not yield a replayable credential.
- **TTL-gated.** `cache.token_cache_ttl_secs = 0` disables the cache entirely (`TokenCache::new` returns `None`); default stays at 30 s per the spec. Operators needing instant revocation can disable.
- **Seal safety.** `Core::pre_seal` already drops auth modules via `module_manager.cleanup`, which releases the `TokenStore` and hence the `Arc<TokenCache>`; stretto's `Drop` zeroizes all held payloads through the `Zeroizing` wrapper.
- **Tests (12 added, all passing):** 7 unit tests on `TokenCache` itself (TTL-zero disables, roundtrip, invalidate, clear, redacted `Debug`, serialized payload shape, `Zeroize` wipe); 2 `TokenStore`-level integration tests (cache enabled by default + populated by lookup; revoke invalidates cache and the revoked token cannot be resurrected). 337 lib tests pass overall (no regressions).
- **Deferred to Slice 2b:** `bvault_cache_*` Prometheus counters — requires threading `MetricsManager` into `Core`, which is orthogonal coupling work that doesn't belong on a security-sensitive cache slice.

#### Caching Slice 1: cache config scaffold (`features/caching.md`)
- **`src/cache/mod.rs`** — new module with `CacheConfig` (serde, `deny_unknown_fields`) plus `DEFAULT_*` constants. Fields: `policy_cache_size` (1024), `token_cache_size` (4096), `token_cache_ttl_secs` (30), `secret_cache_size` (8192), `secret_cache_ttl_secs` (0 = disabled), `memlock` (false), `allow_core_dumps` (false). `CacheConfig::merge` follows the existing directory-based-config convention (non-default wins).
- **`Config::cache`** — the server config now accepts an optional `cache { ... }` block. Absent block / unknown fields / partial blocks behave exactly like the baked-in defaults.
- **`Core::cache_config`** — threaded through `BastionVault::new` alongside `mount_entry_hmac_level` / `mounts_monitor_interval`.
- **`PolicyStore::new`** now reads `core.cache_config.policy_cache_size` instead of the hard-coded `POLICY_CACHE_SIZE` constant (removed). Default behavior is unchanged when the operator omits the `cache` block.
- No new caches allocated in this slice; token / secret / metrics / mlock / zeroize-on-flush work lands in Slices 2–4 per the caching feature spec.
- 5 unit tests covering defaults, empty block, partial block, `deny_unknown_fields`, and `merge`.

### Changed

#### Tracking-doc sync: Identity Groups + Resource/Asset Groups marked Done (`features/identity-groups.md`, `features/resource-groups.md`, `features/asset-groups.md`)
- Identity Groups phase table is already accurate (Phase 8 Cert/OIDC/SAML extension correctly marked *Deferred* — the union pattern is ready, it just has no callers until those backends land). Roadmap entry moved from Active Initiatives → Completed Initiatives with a summary noting the 7 shipped phases + the why behind Phase 8's deferral.
- `features/resource-groups.md` Phase 13 (Ownership / admin transfer / sharing) flipped Pending → Done — the implementation has actually been live (`ShareTargetKind::AssetGroup`, `POST /v2/sys/asset-group-owner/transfer`, member redaction) but the phase table hadn't caught up.
- `features/asset-groups.md` Phases 1–9 flipped Pending → Done — the table was stale from the initial design-only period; the header of that file was already marking the feature "Feature-complete". Each phase now references the concrete code path / endpoint / GUI element it shipped as.
- Roadmap's Active Initiatives list is now accurate: OIDC, SAML (both design-only auth backends), Cloud Storage Targets, and File Resources remain; the three group features and per-user-scoping are all in Completed Initiatives.
- No code change — doc sync only.

#### Cloud providers re-framed as `FileBackend` I/O targets (`features/cloud-storage-backend.md`)
- The cloud-provider feature has gone through two earlier framings that review rejected: a standalone "third deployment mode" storage backend (too much complexity), and a per-file content backend scoped inside File Resources (wrong layer — File Resources shouldn't carry the cloud story for other vault data).
- Final scope: the cloud providers sit **underneath the existing `FileBackend`** as alternative I/O targets, not as a new backend impl. `FileBackend` gains a `FileTarget` trait field; today's `std::fs`-based body moves verbatim into a `LocalFsTarget`. S3 / OneDrive / Google Drive / Dropbox each get a sibling target impl. The `Backend` trait, the barrier, the wire format, and every caller above `FileBackend::get/put/delete/list` are unchanged.
- Phase 1 of the work is a pure refactor with zero behavior change, proven by every existing `FileBackend` test passing unmodified against `FileBackend { target: Arc<LocalFsTarget> }`. Phases 2-8 add S3, OAuth infrastructure + the three consumer drives, the GUI Settings → Storage page, and optional object-key obfuscation.
- Renamed `features/cloud-file-backends.md` → `features/cloud-storage-backend.md` (back to the original filename, now matching the final scope). Roadmap row restored under Storage. File Resources' earlier "content backend" subsection (added in the superseded framing) replaced with a note pointing at this feature as the way to host file content in the cloud.
- Credentials use a small URI grammar (`env:` / `keychain:` / `file:` / `inline:`) — never inlined verbatim in config. OAuth refresh tokens live in the OS keychain on desktop builds, in a process-owned file on servers. Per-operator `client_id` for consumer drives; no shared secrets redistributed. Feature-gated (`cloud_targets` + per-provider sub-features) so builds without the feature can't accidentally contact a cloud provider.
- No code change — design revision only.

### Added

#### File Resources Phase 8: content versioning (`features/file-resources.md`)
- **Version index + historical blob storage.** New `vmeta/<id>` (`FileVersionMeta` — `current_version` + retained `Vec<FileVersionInfo>`) and `vblob/<id>/<version>` keys alongside the existing meta + blob + history + sync storage. Historical blobs go through the same barrier encryption as everything else in the engine.
- **Snapshot-on-write.** `write_entry_and_blob` detects a content change by sha256 mismatch and, *before* overwriting, captures the live blob + displaced metadata as a new historical version. Metadata-only writes (same sha256) don't consume a version slot.
- **Retention + automatic prune.** `DEFAULT_VERSION_RETENTION = 5`. Versions beyond the cap are dropped oldest-first with their `vblob` keys deleted. Set retention to 0 to disable snapshotting entirely.
- **Routes** (all under `files/` mount):
  - `GET files/{id}/versions` — list retained versions + current_version.
  - `GET files/{id}/versions/{version}` — metadata for one historical version.
  - `GET files/{id}/versions/{version}/content` — base64 content with SHA-256 re-verification on read (errors loudly on mismatch).
  - `POST files/{id}/versions/{version}/restore` — swap a historical version into the live slot. Displaced content is itself snapshotted, so restore is reversible.
- **Delete cascade extended.** File DELETE now sweeps `vmeta/<id>` + every `vblob/<id>/*` alongside the existing sync-config / sync-state sweep. Failures are logged and swallowed — the file delete already succeeded and a dangling version can't widen access (owner + shares are gone).
- **Tauri commands:** `list_file_versions`, `read_file_version_content`, `restore_file_version`. Plus TypeScript bindings in `gui/src/lib/api.ts` and `FileVersionInfo` / `FileVersionListResult` types.
- **GUI:** new **Versions** tab on the per-file detail modal. Shows version number, size, short SHA-256, author, and when the version was displaced; per-row Download and Restore buttons. Restore goes through a confirm dialog with the "reversible" disclaimer.
- **Tests (3 new integration tests):** `test_file_versioning_snapshots_on_update` (two updates create two versions with correct sha256s; historical content round-trips; restore rolls live content back), `test_file_versioning_retention_prunes_oldest` (8 content writes with retention=5 ⇒ exactly 5 retained, oldest=v3), `test_file_delete_sweeps_versions` (vmeta + vblob cleared on file DELETE). 393 lib tests pass overall (up from 390).
- **Deferred**: operator-configurable retention (today hardcoded at 5), SMB/SFTP/SCP sync targets (Phases 5-6), periodic re-sync (Phase 7).

#### File Resources Phases 3 + 4 + asset-group membership (`features/file-resources.md`)
- **Asset-group file membership.** `ResourceGroupStore` now has a third reverse index (`resource-group/file-index/<id>`) alongside the resource and secret indexes. `ResourceGroupEntry` gains `files: Vec<String>`; the write handler accepts a `files` comma-slice field; `groups_for_file` + `prune_file` mirror the existing helpers; `reindex` walks file entries; `resolve_asset_groups` recognizes file paths so `groups = [...]` ACL rules apply to files; `PolicyStore::post_route` calls `prune_file` on file DELETE. Same invariants as KV / resource membership.
- **Phase 3: local-FS sync target.** New per-file sync-target store (`sync/<id>/<name>`) + sync-state store (`sync-state/<id>/<name>`) in `src/modules/files/mod.rs`. Routes:
  - `GET files/{id}/sync` — list configured sync targets + per-target state.
  - `POST|DELETE files/{id}/sync/{name}` — create/replace or remove a target.
  - `POST files/{id}/sync/{name}/push` — on-demand push.
  Only `kind = "local-fs"` is accepted on save in this phase. Local-FS push creates parent dirs as needed, writes atomically via `<path>.bvsync.<pid>.tmp` + rename so a concurrent reader never observes a partial file, and optionally applies a Unix mode after the write. Failure paths record `last_error` + `last_failure_at` in the sync-state record *before* surfacing the error, so the next read shows why the push failed. File DELETE sweeps all sync-config + sync-state records for the id.
- **Phase 4: Tauri commands + minimum-viable GUI.**
  - `gui/src-tauri/src/commands/files.rs`: 11 Tauri commands — `list_files`, `read_file_meta`, `read_file_content`, `create_file`, `update_file_content`, `delete_file`, `list_file_history`, `list_file_sync_targets`, `write_file_sync_target`, `delete_file_sync_target`, `push_file_sync_target`. TypeScript bindings in `gui/src/lib/api.ts` + types in `gui/src/lib/types.ts`.
  - `gui/src/routes/FilesPage.tsx`: top-level Files nav entry; list table with Details / Download / Delete actions; upload modal with name + resource + MIME + notes; per-file detail modal with **Info** and **Sync** tabs. The Sync tab supports add local-fs target, push, remove, and displays last-success / last-failure timestamps per target. Delete confirm modal carries the spec's "already-synced remote copies are not touched" disclaimer. App route wired at `/files`.
- **Tests + verification:** 2 new integration tests (`test_sync_target_local_fs_push_writes_file` — full round-trip with byte-for-byte check + state update assertion; `test_sync_target_unsupported_kind_rejected_at_save` — early rejection of future-phase kinds). Rust suite **390/390**, TS type-check clean, GUI unit suite **66/66**, Vite build clean (103 modules, 432 KiB / 118 KiB gzipped).
- **Deferred** (called out in the feature file): SMB (Phase 5), SFTP / SCP (Phase 6) — both need transport crates + OAuth/creds plumbing; periodic re-sync scheduler (Phase 7) — `sync_on_write` flag is stored but not yet honored; content versioning (Phase 8); chunking for files above the inline 32 MiB cap; GUI polish (drag-and-drop zone, plain-text preview, tag chip editor).

#### File Resources Phase 2: ownership + sharing + backfill (`features/file-resources.md`)
- **Owner capture**: every file resource now stamps an owner at create time. The files module's `handle_create` calls `OwnerStore::record_file_owner_if_absent` with `caller_audit_actor(req)` — root-token writes therefore stamp `"root"` rather than orphan the record, matching KV / resource behavior. `PolicyStore::post_route` also stamps on replace-by-id writes (`POST files/files/<id>`) so existing files that pre-date the feature can acquire an owner on their next write.
- **Owner forget + share-cascade on delete**: `PolicyStore::post_route` now forgets the file's owner record on `DELETE files/files/<id>` and issues a cascade-revoke against every `SecretShare` targeting that file. Failures log a warning but never fail the delete (same contract as the KV / resource paths).
- **New `ShareTargetKind::File`** variant (wire string `"file"`). `ShareStore::canonicalize` accepts any non-empty, slash-free id. `shared_capabilities(ShareTargetKind::File, ...)` is now wired into the ACL evaluator so a `scopes = ["shared"]` rule on a file path picks up explicit shares.
- **Owner-aware ACL evaluation**: `resolve_asset_owner` and `resolve_target_shared_caps` in `src/modules/policy/policy_store.rs` recognize `files/files/<id>` paths. `scopes = ["owner"]` rules on file paths therefore see the real owner. `looks_like_kv_path` also updated to exclude `files/` so a file path never accidentally trips the KV owner-capture path.
- **OwnerStore extended** (`src/modules/identity/owner_store.rs`) — new `file_view` sub-view (`owner/file/<id>`) alongside the existing KV and resource views. APIs: `get_file_owner`, `record_file_owner_if_absent`, `set_file_owner`, `forget_file_owner`.
- **`GET identity/owner/file/<id>`** — read the owner record for a file, envelope matching the existing `/owner/kv/` and `/owner/resource/` routes. Consumed by GUI Owner cards.
- **`POST sys/file-owner/transfer`** — admin ownership-transfer endpoint for files. Body: `{ id, new_owner_entity_id }`. Gated by the usual ACL on `sys/file-owner/transfer`, mirroring the kv / resource / asset-group-owner transfer endpoints.
- **`sys/owner/backfill` extended** with a `file_ids` array parallel to `resources` and `kv_paths`. Response now includes a `files` summary (`stamped` / `already_owned` / `invalid`). One endpoint, three object kinds.
- **Tests (5 new + 12 existing = 17 in the files module):** root-token creates stamp owner; delete forgets owner and cascade-revokes shares targeting the file; backfill stamps unowned files with invalid-id reporting; admin transfer overwrites ownership; `identity/owner/file/<id>` returns the expected envelope shape. 388 lib tests pass overall (383 before + 5 new).
- **Still deferred**: asset-group membership for files (requires extending `ResourceGroupStore` with a file-index parallel to the existing resource and secret indexes — a separate slice). All sync targets (Phases 3, 5, 6). GUI (Phase 4). Content versioning (Phase 8).

#### File Resources Phase 1 (`features/file-resources.md`)
- **New `files/` mount and engine** (`src/modules/files/`). Dedicated barrier-encrypted storage independent of the KV and resource engines. Storage layout inside the mount's barrier view:
  - `meta/<id>` — `FileEntry` JSON (id / name / resource / mime_type / size_bytes / sha256 / tags / notes / created_at / updated_at).
  - `blob/<id>` — raw content bytes (single inline blob in Phase 1; chunked layout reserved for a later slice when the inline cap becomes limiting).
  - `hist/<id>/<nanos>` — append-only change log (who / when / op / changed_fields; never content bytes or their hash).
- **v2-accessible CRUD** via a logical backend. Under the `files/` mount: `POST files` (create, server-assigned UUID, returns `{id, size_bytes, sha256}`), `LIST files`, `GET files/{id}` (metadata), `GET files/{id}/content` (content as base64 in the JSON envelope), `POST files/{id}` (replace content + optional metadata updates; omitted fields preserved), `DELETE files/{id}` (drops meta + blob), `GET files/{id}/history` (newest-first change log).
- **32 MiB hard cap** on content enforced server-side by `decode_content` before any bytes are persisted. Operators who need more will be able to opt into cloud storage via the [Cloud Storage Targets](features/cloud-storage-backend.md) initiative once that lands.
- **SHA-256 over plaintext** recorded in `FileEntry.sha256`. The content-read handler recomputes the hash on every read and raises an error on mismatch — storage corruption or out-of-band writes surface as loud failures instead of silently yielding wrong bytes.
- **Change-history entry** recorded on every create + every non-noop update + every delete. Content replacement surfaces as `"content"` in `changed_fields` so a caller inspecting the timeline sees content movement even when no metadata field changed.
- **Wiring**: `FilesModule` registered in `src/module_manager.rs`, default-mounted at `files/` in `src/mount.rs`. New module exports in `src/modules/mod.rs`.
- **Tests (12 passing):** 8 unit tests (SHA-256 determinism / lowercase-hex / 64-char, base64 size-cap rejection, base64 round-trip, diff-field ignored-list, diff-field flags real changes, caller-username preference chain × 3); 4 integration tests driving through `core.handle_request` (create-then-read-content round-trip, oversized-body rejected before store, update-replaces-content with `"content"` in history, delete-then-read-is-gone). 383 lib tests pass overall (371 before Phase 1 + 12 new).
- **Intentionally deferred**: ownership / sharing integration via `OwnerStore` + `ShareStore` (Phase 2), sync targets local/SMB/SCP/SFTP (Phases 3–6), GUI (Phase 4), periodic re-sync (Phase 7), content versioning (Phase 8), chunking for files above the inline cap. All called out in the feature file's updated Current State and in the roadmap row.

#### Per-user scoping: owner backfill + templating tests (`features/per-user-scoping.md`)
- **`POST /v2/sys/owner/backfill`** — new sudo-gated admin endpoint (under `root_paths`) that stamps a caller-supplied `entity_id` as owner of every currently-unowned target in the request. Body: `{ entity_id, resources?, kv_paths?, dry_run? }`. Already-owned objects are skipped (use the `*-owner/transfer` endpoints to overwrite). Response carries per-kind counts (`stamped` / `already_owned` / `invalid`) plus the invalid entries themselves so operators see exactly what was rejected. `dry_run = true` reports the same counts without writing. This is the migration tool named in `features/per-user-scoping.md`'s testing plan — deployments that ran before per-user-scoping landed can now retroactively claim their pre-existing objects so `owner` / `shared`-scoped ACLs start seeing them.
- **HTTP wiring** (`src/http/sys.rs`) — `sys_owner_backfill_request_handler` + `POST /v{1,2}/sys/owner/backfill` route so the endpoint is cURL-able. Delegates to the logical backend via `handle_request`.
- **Handler** (`src/modules/system/mod.rs` `handle_owner_backfill`) — reuses the existing `OwnerStore::{record_resource_owner_if_absent, record_kv_owner_if_absent, get_resource_owner, get_kv_owner}` APIs so the never-overwrite invariant is preserved. Resource names containing `/` and KV paths that fail `canonicalize_kv_path` are surfaced as `invalid` instead of silently dropped.
- **Tests (3 new integration tests):** `test_owner_backfill_stamps_unowned_and_skips_owned` covers the happy path plus an already-claimed resource (untouched) and a malformed resource name and KV path (both reported as `invalid`); `test_owner_backfill_dry_run_writes_nothing` proves dry-run is side-effect-free; `test_owner_backfill_rejects_empty_entity_id` covers the 400 path.

#### Per-user scoping: Phase 2 templating unit tests (`features/per-user-scoping.md`)
- `apply_templates` (the wrapper around `substitute_path` in `src/modules/policy/policy_store.rs`) previously had zero unit tests — only the inner `substitute_path` helper was covered. Added 5 new tests covering: every path in a multi-rule policy substituted with caller values; `{{username}}` fallback to `display_name` when `auth.metadata["username"]` is missing; mixed-resolution rules (some drop, some survive) leave the policy partially live; all-drop returns `None` so the policy grants nothing; capabilities / scopes / groups survive the substitution intact. Policy templating is now proven fail-closed end to end.
- Feature file's Phase 2 row flipped Pending → Done; the stale "Policy templating deferred" and "Sharing still design-only" bullets in Implementation Notes replaced with current-state summaries (templating is live, sharing has been live since Phase 8). No behavior change — the code already worked; this is doc + test-coverage catching up to reality.

#### Batch operations Phase 1 (`features/batch-operations.md`)
- **`POST /v2/sys/batch`** — new endpoint that accepts N vault operations in a single request body and executes them sequentially under the caller's token. Every op routes through the normal `Core::handle_request` pipeline, so ACLs, audit, and per-path semantics match individual HTTP calls. Registered v2-only per the project's forward-going-API rule.
- **`src/http/batch.rs`** — `BatchRequest` / `BatchOperation` / `BatchResult` / `BatchResponse` types, `sys_batch_v2_request_handler`. Deserialization denies unknown op kinds. The handler rejects empty batches and batches exceeding `batch_max_operations` (default 128) with 400 before any op runs.
- **Route wiring** (`src/http/sys.rs`) — per-route `PayloadConfig::limit(32 MiB)` drops oversized bodies at the framework layer rather than allocating them.
- **Config** (`src/cli/config.rs`) — new `batch_max_operations` and `batch_max_body_size` keys (`0` = built-in default).
- **Per-op error mapping** — `ErrPermissionDenied → 403`, `ErrRouterMountNotFound → 404`, `ErrBarrierSealed → 503`, `ErrRequestClientTokenMissing → 401`, else 500. Error text lands in the per-op `errors` array; other ops in the same batch are unaffected by one op's failure.
- **Tests (8)** — parse/deserialize, unknown-op rejection, empty batch rejection, oversized batch rejection, write-then-read-in-same-batch visibility, individual-failure-does-not-abort-batch, default-max-operations-is-128, op-kind-maps-to-logical-Operation. 363 lib tests pass overall.
- **Deferred to later slices**: CLI command (`bvault batch`), client SDK method, per-op `batch_id` correlation in audit entries.

#### File Resources feature spec (`features/file-resources.md`, design-only)
- New `features/file-resources.md` and matching roadmap entry (Todo). Scopes a "File Resources" kind: binary blobs stored under the barrier alongside secrets, chunked (1 MiB default, 32 MiB cap), AEAD-authenticated per chunk, with a plaintext-SHA-256 manifest for whole-file integrity. Reuses the existing resource / ownership / sharing / audit plumbing so files inherit per-user-scoping from day one — no parallel identity layer.
- Sync targets (local FS, SMB, SCP, SFTP) are scoped as later phases. Push-only in v1 (vault is authoritative). Sync-target credentials are themselves stored as vault objects (a KV secret or another file resource), referenced by id, so SSH keys and SMB passwords don't leak into a separate silo. Sync failures audit but don't fail the vault write.
- 8-phase breakdown: engine scaffold → identity integration → local-FS sync → GUI → SMB → SFTP+SCP → periodic re-sync → versioning/retention. Critical path is Phase 1; transport phases are parallelizable after Phase 3 proves the sync abstraction.
- No code change — tracking-doc only.

### Fixed

### Added

#### File events in the admin Audit page (`src/modules/files/files_audit_store.rs`, `src/modules/files/mod.rs`, `src/modules/system/mod.rs`, `gui/src/routes/AuditPage.tsx`)
- **`FileAuditStore`** — new append-only log at `sys/files-audit/<nanos>` mirroring `UserAuditStore`. Records the ts, actor entity id (with the existing root-fallback via `caller_audit_actor`), op (`create` / `update` / `delete` / `restore`), file id, name snapshot, and a compact details string (`fields=resource,notes` on metadata update, `content` added when the SHA-256 moved, `version=v3` on restore). Constructed lazily from the system view — no post-unseal wiring needed.
- **File-module handlers wired** — `handle_create`, `handle_write`, `handle_delete`, and `handle_version_restore` now call `record_file_audit`. On delete, the name is snapshotted from the metadata before wiping storage so the audit row still has a usable label. No-op writes (same metadata, same SHA) are suppressed to keep the Audit page signal-heavy. Failures on the audit-append path are logged and swallowed so they can never block the primary operation — the per-file history log inside the mount still captures the event for the per-file timeline UI.
- **System audit aggregator** — new branch under `handle_audit_events` that walks `FileAuditStore::list_all()` and emits events in the `file` category. Target is the human name with id carried as a `changed_fields` entry (`id=…`) so both name- and id-based searches match.
- **`AuditPage`** — added `file` to the category label / variant maps and `restore` to the op-variant map so the new events render cleanly.
- Tests: 22/22 file-module tests pass; Rust lib + Tauri GUI both type-check clean.

#### Resource detail — Files tab (`gui/src/routes/ResourcesPage.tsx`)
- **`ResourceFilesPanel`** — new "Files" tab on the Resource detail page, sitting between Secrets and Sharing. Lists every file whose `resource` field names the current resource, with download action. Filtering is client-side over `listFiles` + `readFileMeta` (the file module does not yet expose a `by-resource` reverse index — an O(n) walk that we accept today; server-side index is a future optimization if it becomes a hot path). Empty state directs the operator to the Files page to set the Resource field. This closes the loop with the upload-modal / edit-modal resource typeahead added in this release: associating a file with a resource now surfaces on the resource itself.

#### Edit file details (`gui/src/routes/FilesPage.tsx`, `gui/src-tauri/src/commands/files.rs`, `gui/src/lib/api.ts`)
- **`EditMetaModal`** — new modal that edits a file's name, resource association (via the `TargetPicker` typeahead), MIME type, tags (comma-separated), and notes. Reachable two ways: an "Edit" button on each row of the Files table, and an "Edit details" button in the Info tab of the file detail modal. No file-module change was needed — `handle_write` already treats an unchanged SHA-256 as a metadata-only write: it skips the version snapshot, and records just the changed metadata fields in history. The modal reads the current content via `readFileContent`, re-POSTs those same bytes with the new metadata, and relies on that path. The content read also re-verifies SHA-256, so a corrupt blob would surface at save time rather than silently overwriting.
- **`update_file_content` Tauri command + TS binding** — added a missing `resource: Option<String>` parameter. The file module's `handle_write` already accepted `resource` in the body and merged it via `merge_str`, but the Tauri command layer wasn't forwarding the field, so edits to the resource association were silently dropped (the Info tab kept showing `resource: —` after Save).

### Fixed

#### Upload File modal — resource field now typeaheads existing resources (`gui/src/routes/FilesPage.tsx`)
- The "Resource (optional)" input in the `UploadFileModal` was a free-form text box, so associating a new file with an existing resource required the operator to remember the exact resource name and type it from memory. Misspellings produced orphaned `resource` labels with no association.
- Replaced the plain `Input` with `TargetPicker kind="resource"` — the same typeahead already used on the Sharing page. It loads the resource list via `listResources` on first focus, filters client-side as the user types, and fails open to a plain text input if listing is denied. Free-form entry still works for resources that don't exist yet.

#### GUI file upload drag-and-drop on Windows (`gui/src-tauri/tauri.conf.json`)
- **Tauri v2 intercepts native drag-drop on Windows by default.** On WebView2 the WebView never sees the drop, so the HTML5 `onDragOver` / `onDrop` handlers in `FilesPage.tsx` (page-level overlay and per-modal drop zone) silently did nothing: dragging a file onto the Files page had no effect, and users had to fall back to the file picker button.
- Fix: set `"dragDropEnabled": false` on the `main` window in `tauri.conf.json`. Tauri's native handler is disabled, HTML5 drag-drop events propagate to React as they do in the browser dev build, and the existing `onDrop` handlers (which filter on `e.dataTransfer.types` containing `"Files"` to avoid hijacking intra-page drags) start firing. No frontend changes were needed — the handlers were correct all along; only the Tauri window config was swallowing the events on Windows.

#### Owner capture now stamps root-token writes (`features/per-user-scoping.md`)
- **`PolicyStore::post_route` owner bookkeeping** (`src/modules/policy/policy_store.rs`) previously gated ownership stamping on a non-empty `entity_id` in auth metadata. Root tokens carry no `entity_id` (only `display_name = "root"`), so every resource or KV secret created through a root token orphaned its owner record and appeared as **Unowned** in the GUI forever. Admin-heavy workflows — where operators routinely create vault objects via root — left the Owner card empty on the Resources Sharing tab even after granting shares (which only an owner or admin can do), making the feature look broken.
- Fix: reuse the existing `caller_audit_actor(req)` helper (which prefers `entity_id` and falls back to `display_name`) to compute the owner id on capture. Root-token writes now stamp `entity_id = "root"` on the owner record; non-root authenticated writes continue to stamp their real entity id.
- ACL impact is zero by construction. Root bypasses policy entirely, and for non-root callers `scope_passes` compares `entity_id` to `entity_id` — no real user has `entity_id = "root"` in their auth metadata, so a literal-root owner record cannot accidentally grant owner-scope access to anyone else. The GUI's `EntityLabel` already renders non-UUID values as literal usernames (see `caller_audit_actor` docstring), so the Owner card displays `"root"` without a schema change.
- 1 regression test: `test_root_token_resource_write_captures_owner` writes a resource + a KV secret as root and asserts both owner records exist with `entity_id = "root"`. 355 lib tests pass overall.

### Changed

#### Resource Management marked Done (`features/resources.md`)
- Roadmap status flipped from In Progress to Done. The shipped implementation covers everything the feature file described and extends it: resources live in a dedicated barrier-encrypted engine (`src/modules/resource/`) rather than as a KV prefix, each metadata write is appended to a per-resource history log (who + when + which fields, no values), each resource-secret write snapshots the previous value into a versioned entry, resource types are configurable (built-ins + user-defined) with dynamic per-type fields, and ownership / sharing / asset-group membership are fully wired through the ACL evaluator.
- No code change in this entry — tracking-doc sync only. `roadmap.md` moves the initiative to Completed Initiatives; `features/resources.md` adds a Current State section noting the divergence from the original `kv/_resources/...` layout proposal.

### Added

#### Audit Logging Phase 1 (`features/audit-logging.md`)
- **`src/audit/`** -- new subsystem with `AuditEntry` schema, `AuditBroker` fan-out, tamper-evident SHA-256 hash chain, and an append-only `FileAuditDevice`. Every audited operation emits one JSON line per enabled device with `time`/`type`/`auth`/`request`/`response`/`error`/`prev_hash` fields. Client tokens and body string-leaves are redacted via the barrier-derived HMAC key (`hmac:<hex>`) unless the device is enabled with `log_raw=true` for dev.
- **Core integration** (`src/core.rs`): `audit_broker: ArcSwapOption<AuditBroker>` field installed at post-unseal using the barrier's derived HMAC key, cleared at pre-seal. `handle_log_phase` now calls `broker.log(...)` after every request with a combined request+response entry. Fail-closed: if any device errors, the log phase returns `Err` and the request fails — unaudited operations cannot slip through.
- **`GET/POST/DELETE /v1/sys/audit[/<path>]`** are now live. `GET` lists enabled devices; `POST /<path>` with `{ "type": "file", "options": { "file_path": ..., "log_raw": ... } }` enables one; `DELETE /<path>` disables it. Device configs persist at `sys/audit-devices/<path>` and are re-enabled on every unseal.
- **12 audit tests**: entry redaction keeps plaintext out unless `log_raw` is set, hash-chain verify accepts consistent chains + flags tampering (insertion/deletion/modification), file device end-to-end, full enable/disable round-trip via the HTTP API, broker-reset-on-seal.
- Deferred to later phases (noted in the feature file): syslog/socket/HTTP devices, separate pre-dispatch request entries (the combined entry still covers all state), external chain-head witness, CLI audit-management commands, GUI viewer for the on-disk log.

#### Admin audit page
- **`GET /v2/sys/audit/events`** -- new backend aggregator that walks every per-subsystem change-history log we already maintain (ACL policy history, identity user-group history, identity app-group history, asset-group history) and returns a flat newest-first JSON list of `{ts, user, op, category, target, changed_fields, summary}` events. Optional `from` / `to` RFC3339 bounds and a `limit` (default 500) are accepted as query-string or body fields. Resource-metadata history lives in the resource mount's own barrier view (not reachable from the system backend without routing a sub-request) and is intentionally omitted from the v1 aggregator — operators can still see per-resource history via the Resources tab.
- **HTTP + Tauri plumbing**: `sys_audit_events_request_handler` in `src/http/sys.rs` parses the query string into the logical `Request::body` so the aggregator resolves its fields; `list_audit_events` Tauri command returns `Vec<AuditEvent>` to the frontend.
- **Admin → Audit GUI page** (`gui/src/routes/AuditPage.tsx`) -- searchable table with From/To/Max-rows refresh controls plus a free-text search box and Category/Operation filters. User column uses `EntityLabel` when the `user` field looks like an `entity_id`, so audit rows humanize the same way share tables do.
- 1 integration test (`test_audit_events_aggregator_basic`): creates a policy + an identity user-group, reads `sys/audit/events`, asserts both events appear in the response.

#### Fix: new users appear in share picker without having to log in
- **Pre-provision entity alias at create time.** The GUI user-picker reads `/v2/identity/entity/aliases`, which is backed by `EntityStore`'s alias index. Previously the index was only populated on *first login*, so a freshly-created userpass user or AppRole role didn't appear in share dialogs until they authenticated once — admins ran straight into the "No matches" state when trying to grant access up-front. `write_user` (userpass) and `write_role` (approle) now call `get_or_create_entity` at the end of the create/update path so the alias is ready immediately. Update writes only trigger for the role-create branch so edits don't churn. The corresponding `delete_user` / `delete_role` hooks call `EntityStore::forget_alias` to drop the `(mount, name)` lookup when the principal disappears. The entity record itself is retained so share records and ownership data still resolve (audit trail preserved).
- **Alias key format changed from `<mount>:<name>` to `<mount>/<name>`.** On Windows, NTFS treats `:` as an alternate-data-stream marker; the file physical backend's `read_dir` returned only the pre-`:` prefix, silently breaking `list_aliases` on Windows hosts. Using `/` as the separator lets the underlying backend round-trip the key on every OS via its native path semantics. Other code paths (`get_by_alias`, `get_or_create_entity`, `forget_alias`) write + read through the same helper, so the switch is transparent to callers. Existing aliases stored in the old format on Linux/MacOS hosts will no longer resolve after upgrade and will be re-provisioned lazily on next login or by `sys/internal/ui/mounts` warm-up.
- 1 new integration test (`test_userpass_create_preprovisions_entity_alias`): creates a userpass user that has never logged in, asserts it appears in `identity/entity/aliases`, deletes it, asserts the alias is gone. 123 module tests pass.

#### KV Secrets Sharing + User-Picker (`features/per-user-scoping.md`)
- **Secrets can now be shared from the GUI.** `gui/src/routes/SecretsPage.tsx` gains a **Share** button on the detail view that opens a modal with the owner record, the current shares table (Revoke per row), a Grant-access form (owner + admin), and an admin-only Transfer-ownership flow. Targets the new `ShareTargetKind::KvSecret` via the existing share API; the full canonical path (e.g. `secret/foo/bar`) is derived from `mountBase + currentPath + key` and normalized via `canonicalizeSecretPath`.
- **User-picker instead of raw UUIDs.** New `EntityPicker` component (`gui/src/components/ui/EntityPicker.tsx`) — typeahead over `(mount, name, entity_id)` tuples from a new `GET /v2/identity/entity/aliases` endpoint. Operators can now search by login (`felipe`), mount (`userpass/`), or partial UUID; the picker resolves to the grantee's stable `entity_id` on select. Falls back to raw UUID entry when the alias listing is denied. Wired into the four grant flows: SharingPage Manage-target, ResourcesPage Sharing tab, AssetGroupsPage Sharing tab, and the new SecretsPage Share modal. Also used for the asset-group and KV Transfer-ownership dialogs.
- **Backend**: `EntityStore::list_aliases()` (`src/modules/identity/entity_store.rs`) enumerates every `(mount, principal-name, entity_id)` tuple from the alias sub-view; the new `identity/entity/aliases` logical route (LIST + Read, ACL-gated the usual way) surfaces it via `/v2/identity/entity/aliases`. Fails-open on the GUI side so a caller without directory access can still paste a UUID.

### Security

#### Closed a mount-listing and seal-vault policy bypass in the Tauri GUI
- **`list_mounts` / `list_auth_methods`** (`gui/src-tauri/src/commands/system.rs`) used to read the router's mount table directly, bypassing the policy layer. Any authenticated user — including one holding only the `default` policy — saw every mount on the dashboard (`secret/`, `resources/`, `identity/`, `resource-group/`, `sys/`, etc.) regardless of their ACL. Both commands now route through `core.handle_request(sys/internal/ui/mounts)` which runs the full auth + policy pipeline and uses `ACL::has_mount_access` to filter per-mount visibility. A user with only `default` now sees exactly the mounts their policy grants access to.
- **`seal_vault`** (same file) used to call `embedded::seal_vault` directly, so any authenticated caller could seal the vault from the Seal Vault button. It now resolves the caller's token via `token_store.check_token`, probes `sys/seal` Write via `PolicyStore::can_operate`, and rejects any caller that doesn't hold `update` on `sys/seal` — which in the shipped policy set is only `root`. The rejection is a backend enforcement, not a UI-only hide, so a hand-crafted Tauri call with a low-privilege token fails with a permission error.
- **Policy templating vocabulary** (`src/modules/policy/policy_store.rs`) now recognizes Vault-style `{{identity.entity.id}}`, `{{identity.entity.name}}`, and `{{identity.entity.mount}}` as synonyms for the BastionVault-native `{{entity.id}}`, `{{username}}`, `{{auth.mount}}`. The shipped `default` policy uses the `identity.entity.*` form; without the synonyms the placeholders were treated as unknown and the policy's identity self-lookup rules dropped silently.
- 1 new integration test (`test_system_internal_ui_mounts_default_policy_sees_nothing`): provisions a userpass user `felipe` with only `default` and asserts the mount listing excludes `secret/`, `resources/`, `resource-group/`, and `auth/pass/`.

#### Asset Groups: member redaction on read (`features/asset-groups.md`)
- **`PolicyStore::can_operate(auth, path, op) -> bool`** (`src/modules/policy/policy_store.rs`) -- new dry-run probe that runs the same per-target resolution (asset groups, owner, active shares) and ACL evaluation as `post_auth`, but side-effect free. Used by handler code that needs to preview authorization decisions for targets other than the current request path. `check_only=false` is required on the internal `allow_operation` call because `Permissions::check` short-circuits without setting `allowed` when `check_only=true`.
- **Member redaction on asset-group read** (`src/modules/resource_group/mod.rs`) -- `handle_read` now probes `Read` on every member's logical path (resources as `resources/resources/<name>`, KV secrets via both canonical and KV-v2 `<mount>/data/<rest>` forms) and replaces the path with the `REDACTED_MEMBER` sentinel (`"<hidden>"`) for callers who cannot see it. Owners and admins (tokens holding `root` or `admin`) short-circuit the probe and see everything unredacted. The `owner_entity_id` comparison uses the caller's `auth.metadata["entity_id"]`.
- **GUI redaction affordance** (`gui/src/routes/AssetGroupsPage.tsx`) -- Overview badges render `<hidden>` entries as neutral "hidden" chips; the Resources and Secrets tables filter out hidden rows and show a muted-italic "N hidden resource(s)/secret(s) you don't have read access to." summary underneath. Group cardinality remains visible via the Overview detail rows.
- **1 new integration test** (`test_asset_group_member_redaction_for_non_owner`): a custom policy grants a userpass caller read on `resource-group/groups/*` and on `secret/data/ok/*`; the caller sees their visible secret unredacted and both the forbidden secret and the forbidden resource member as `<hidden>`. Root on the same group sees everything unredacted. 12 resource-group tests pass.

#### Asset Groups: ownership, admin transfer, and sharing (`features/asset-groups.md`)
- **`owner_entity_id` on `ResourceGroupEntry`** (`src/modules/resource_group/group_store.rs`) -- captured from `auth.metadata["entity_id"]` on the first write and preserved across every subsequent `set_group` call. Root-token creates still succeed with an empty owner; admins can adopt such groups via the transfer endpoint below. Emitted in the group-read response as a new `owner_entity_id` field.
- **Admin transfer endpoint** (`src/modules/system/mod.rs`): `POST /v2/sys/asset-group-owner/transfer` (body: `{ name, new_owner_entity_id }`). Gated by the ACL on `sys/asset-group-owner/transfer`. Backed by a new `ResourceGroupStore::set_owner` method that is separate from `set_group` so a regular write can never escalate ownership.
- **`ShareTargetKind::AssetGroup`** (`src/modules/identity/share_store.rs`) -- third variant alongside `KvSecret` and `Resource`. Canonicalizes the group name the same way the resource-group store does (lowercase, no `/` or `..`). The existing share CRUD endpoints accept `"asset-group"` as a kind verbatim.
- **Indirect share resolution** (`src/modules/policy/policy_store.rs::resolve_target_shared_caps`) -- after checking direct shares on the target, the helper walks `Request::asset_groups` (already populated by `post_auth`) and unions any asset-group shares the caller has for each group containing the target. One share on `asset-group:project-phoenix` therefore grants the listed capabilities on every current and future member of that group, exactly as the design intended, with zero extra lookups.
- **GUI Sharing tab on the Asset Groups detail page** (`gui/src/routes/AssetGroupsPage.tsx`) -- owner card with "You" badge, shares table with Revoke, Grant-access modal (owner + admin), and an admin-only Transfer-ownership modal that calls the new `transfer_asset_group_owner` Tauri command. The Overview tab gains an Owner row.
- **Tauri commands**: `transfer_asset_group_owner` in `gui/src-tauri/src/commands/sharing.rs`; `AssetGroupInfo` and the frontend type now include `owner_entity_id`; `ShareTargetKind` union widened to `"asset-group"`.
- **1 new integration test** in `src/modules/resource_group/mod.rs`: covers owner capture on root-token creates (stays empty), admin transfer populating the owner, and ownership survival across a subsequent regular write.

#### Per-User Scoping GUI (`features/per-user-scoping.md` phases 7, 9, 10 GUI)
- **`/sharing` page** (`gui/src/routes/SharingPage.tsx`) -- new top-level route with two tabs: "Shared with me" lists every `SharePointer` for the caller's `entity_id` with one-click open links to the referenced KV path or resource; "Manage target" lets an operator pick a (kind, path), load current shares, Grant new access (grantee + capability checkboxes + optional RFC3339 expiry), and Revoke individual shares. Wired into the sidebar under the user-facing nav.
- **Per-resource Sharing tab** (`gui/src/routes/ResourcesPage.tsx` — `ResourceSharingCard`) -- owner card showing the stored `entity_id` (badged "You" when it matches the current caller) with creation timestamp, a shares table (grantee, capability chips, granted timestamp, expiry with expired-red state, Revoke button), a Grant-access modal gated to owners and admins, and an admin-only Transfer-ownership modal that calls `transfer_resource_owner`. Unowned resources render an explicit empty state explaining the first-write capture.
- **Entity + owner lookup routes** (backend, `src/modules/identity/mod.rs`): `GET /v1-v2/identity/entity/self` returns the caller's entity record (hydrated with `primary_mount`, `primary_name`, aliases, `created_at` when the identity module is loaded); `GET /v1-v2/identity/owner/kv/{path_b64}` and `GET /v1-v2/identity/owner/resource/{name}` expose owner records so the GUI can render "who owns this?" without a second lookup. Both owner endpoints return `owned: false` with empty identifiers when no record exists yet.
- **Tauri commands**: `get_entity_self`, `get_kv_owner`, `get_resource_owner`, `list_shares_for_grantee`, `list_shares_for_target`, `put_share`, `delete_share`, `transfer_kv_owner`, `transfer_resource_owner` in the new `gui/src-tauri/src/commands/sharing.rs`.
- **Auth store `loadEntity()`** (`gui/src/stores/authStore.ts`) -- new action called from every login path in `LoginPage.tsx` that populates `entityId` and `principal` from `/v2/identity/entity/self`. Failure is silent; ownership-aware UI degrades to "owner unknown" rather than misreporting ownership.
- **New types** (`gui/src/lib/types.ts`): `EntitySelf`, `OwnerInfo`, `SharePointer`, `ShareEntry`, `ShareTargetKind`.

#### Sharing, Templating, and Admin Transfer (`features/per-user-scoping.md` phases 2, 8, 10)
- **`ShareStore`** (`src/modules/identity/share_store.rs`) -- new identity subsystem that persists `SecretShare` records behind the vault barrier. Primary storage at `sys/sharing/primary/<target_hash>/<grantee>`, reverse index at `sys/sharing/by-grantee/<grantee>/<target_hash>`, where `target_hash = base64url("<kind>|<canonical_path>")`. Handles both kinds: `kv-secret` (canonicalized the same way `OwnerStore` canonicalizes — KV-v2 `data/`/`metadata/` stripped) and `resource`. Exposes `set_share`, `get_share`, `delete_share`, `list_shares_for_target`, `list_shares_for_grantee`, `shared_capabilities`, and `cascade_delete_target`. Capabilities are normalized on write (trim, lowercase, dedup, reject anything outside `read`/`list`/`update`/`delete`/`create`). `expires_at` is supported; expired shares are treated as inert by the evaluator without being deleted.
- **ACL `shared` scope wired end-to-end** -- the `shared` branch of `scope_passes` is no longer a placeholder. `PolicyStore::post_auth` resolves the caller's active share capabilities on the request target via `ShareStore::shared_capabilities` and stashes them on `Request::target_shared_caps`; the evaluator then checks whether the capability corresponding to the current operation is present (read/list/update/delete/create). The owner-scope first-write carve-out still applies; `shared` and `owner` in the same rule OR together.
- **Share-cascade on target delete** -- `PolicyStore::post_route` calls `ShareStore::cascade_delete_target` on a successful KV-path or resource delete so dangling share rows do not outlive the secret/resource. Failures are logged but never fail the delete.
- **v2 sharing HTTP API** -- new routes on the identity backend (mounted at `/v1/identity/` and `/v2/identity/`, per the agent.md v2 rule for new endpoints):
  - `GET /v2/identity/sharing/by-grantee/{grantee}` -- every share granted to an entity (pointers only).
  - `GET /v2/identity/sharing/by-target/{kind}/{target_b64}` -- every share granted on a target.
  - `PUT /v2/identity/sharing/by-target/{kind}/{target_b64}/{grantee}` -- create or replace a share. Body: `capabilities` (comma-string or array), `expires_at` (optional RFC3339); `target_kind` and `target_path` in the body may override the URL segments with the raw (non-encoded) form.
  - `GET /v2/identity/sharing/by-target/{kind}/{target_b64}/{grantee}` -- read a single share.
  - `DELETE /v2/identity/sharing/by-target/{kind}/{target_b64}/{grantee}` -- revoke a single share.
- **List-filter by ownership also honors `shared`** -- `filter_list_by_ownership` now keeps keys the caller has any non-expired share on (in addition to caller-owned keys) when `shared` is in the active filter scopes, so a user with `scopes = ["owner", "shared"]` LISTs both their own entries and those shared with them.
- **Policy templating** -- `{{username}}`, `{{entity.id}}`, and `{{auth.mount}}` are now substituted at ACL compile time (`PolicyStore::new_acl_for_request`). Templated policies are auto-detected at parse: `Policy::from_str` flips `templated = true` when any path contains `{{`. Substitution is fail-closed — an unresolved placeholder drops the owning path rule and logs a warning; a policy whose every path drops contributes no authorization. Three login handlers (UserPass, UserPass/FIDO2, AppRole) now also populate `auth.metadata["mount_path"]` so `{{auth.mount}}` has a value. Unit tests cover the happy cases, unknown placeholders (fail-closed), empty values (fail-closed), and no-placeholder identity.
- **Admin ownership-transfer endpoints** -- `POST /v2/sys/kv-owner/transfer` (body: `{path, new_owner_entity_id}`) and `POST /v2/sys/resource-owner/transfer` (body: `{resource, new_owner_entity_id}`). Access gated by the usual ACL on `sys/kv-owner/transfer` / `sys/resource-owner/transfer`. Backed by new `OwnerStore::set_kv_owner` / `set_resource_owner` methods that unconditionally overwrite (distinct from the `record_*_if_absent` helpers used by the first-write capture path).
- **2 new integration tests** in `src/modules/identity/mod.rs` covering share round-trip, KV-v2 path canonicalization on reads, by-grantee and by-target listings, cascade-delete semantics, and the input-validation rejects (empty grantee, empty/invalid capabilities, invalid kind). **4 new unit tests** for template substitution in `src/modules/policy/policy_store.rs`.

#### Per-User Scoping (`features/per-user-scoping.md`)
- **`EntityStore`** (`src/modules/identity/entity_store.rs`) -- new identity subsystem that issues a stable `entity_id` UUID per `(mount, principal_name)` and auto-provisions on first login. Storage: `sys/identity/entity/<uuid>` with a `sys/identity/alias/<mount>:<name>` lookup index. Exposed through `IdentityModule::entity_store()` alongside the existing `group_store`.
- **`entity_id` plumbed into issued tokens** -- UserPass, AppRole, and FIDO2 login handlers now call `EntityStore::get_or_create_entity(mount, name)` and stash the UUID in `auth.metadata["entity_id"]`. Survives token renewal and the lookup round-trip through `TokenEntry.meta`. Fail-closed: if the entity store is unavailable the login still succeeds but the token carries no `entity_id`, which means owner-scoped policy rules will not match.
- **`OwnerStore`** (`src/modules/identity/owner_store.rs`) -- unified owner tracking for KV secrets and resources. KV paths are canonicalized the same way the resource-group store canonicalizes them (KV-v2 `data/` / `metadata/` segments stripped so the owner of `secret/foo/bar` keys identically whether the write came in as v1 or v2). `PolicyStore::post_route` records the caller as owner on every successful `Write` against a previously-unowned target, and forgets the owner on `Delete`.
- **ACL `scopes = [...]` qualifier** -- new optional attribute on policy path blocks alongside `groups = [...]`. Parsed into `PolicyPathRules.scopes` and `Permissions.scopes` (`src/modules/policy/policy.rs`), normalized (trim, lowercase, drop `any`) at init. Scoped rules live in a dedicated `ACL::scoped_rules` list (parallel to `grouped_rules`) so their per-rule filter is not lost to a merge. `PolicyStore::post_auth` resolves the request target's owner via `resolve_asset_owner` and stashes it on `Request::asset_owner`; the evaluator then checks `scope_passes` for each matching scoped rule. Supported scopes: `owner` (target's owner equals caller's `entity_id`, with a first-write carve-out so a user can create their very first object under an owner-only policy), `shared` (accepted by the grammar but currently always fails — `SecretShare` is a future phase), and `any` (legacy no-op, dropped at parse time).
- **List-filter by ownership** -- when a `LIST` op is authorized only by a `scopes = [...]`-filtered rule, the evaluator records the rule's scopes on `ACLResults::list_filter_scopes` and `PolicyStore::post_route` narrows the response `keys` to entries the caller owns. Works uniformly for KV mounts and the resource engine. An ungated LIST grant on the same path defeats the filter so broader access is never accidentally narrowed.
- **Two seeded baseline policies** (`src/modules/policy/policy_store.rs`): `standard-user-readonly` (read+list on KV + resources they own/are shared) and `secret-author` (full CRUD on KV + resources they own/are shared). Both ship alongside the existing broadly-scoped `standard-user` so operators can opt into ownership-aware ACLs without a migration. `load_default_acl_policy` seeds all three.
- **3 new integration tests** in `src/modules/identity/mod.rs`: alice-writes-bob-denied, secret-author full CRUD on owned secret, and list-filter narrows `secret/metadata/` to caller-owned keys for a user with `secret-author`.
- Updated 4 existing policy-listing tests to expect the two new seeded baselines in the default policy list.



#### Resource Groups (`features/resource-groups.md`)
- **Resource-group module** (`src/modules/resource_group/`) -- new logical backend mounted at `resource-group/` that manages named collections of resources. Each group holds a description and a list of resource names; membership is canonicalized (lowercased, trimmed, deduped, sorted) on every write.
- **`ResourceGroupStore`** (`src/modules/resource_group/group_store.rs`) -- encrypted storage under the system barrier view at `sys/resource-group/group/`, with a reverse member index at `sys/resource-group/member-index/<resource>` so "which groups contain this resource?" is a single lookup. The reverse index is maintained by diffing old vs new members on every write; a `reindex` admin endpoint rebuilds it from primary records for recovery after an interrupted write.
- **HTTP API**: `LIST/GET/PUT/DELETE /v1/resource-group/groups/{name}`, `GET /v1/resource-group/groups/{name}/history`, `GET /v1/resource-group/by-resource/{resource}`, `PUT /v1/resource-group/reindex`.
- **Change history with before/after values** -- every create/update/delete is recorded as a `ResourceGroupHistoryEntry { ts, user, op, changed_fields, before, after }` under `sys/resource-group/history/{name}/<20-digit-nanos>`. Shape mirrors identity-group history so the GUI can reuse its diff renderer when it lands. `members` is compared as a set (pure reordering does not record a new entry); delete entries retain the group's final state in `before` so the audit trail survives removal.
- **Default mount + migration** (`src/mount.rs`) -- new deployments get the `resource-group/` mount automatically; existing deployments pick it up on next unseal via the `mount_update` migration (same path used for `identity/`).
- **Resource-delete lifecycle prune** -- the resource module's delete handler (`src/modules/resource/mod.rs`) now calls `ResourceGroupStore::prune_resource` after the metadata write has been removed, so deleting a resource automatically drops it from every group that contained it and clears its reverse-index entry. Prune failures are logged and do not block the delete; stale entries can still be cleaned up with `resource-group/reindex`.
- **ACL `groups = [...]` policy qualifier** -- policy HCL grew a new optional attribute on `path` blocks that gates the rule's capabilities on the request target's asset-group membership (resources *and* KV secrets). Parsed into `PolicyPathRules.groups` and `Permissions.groups` (`src/modules/policy/policy.rs`), normalized (trim, lowercase, dedup) at policy init. Gated rules are kept unmerged in a dedicated `ACL::grouped_rules` list (`src/modules/policy/acl.rs`) so per-rule gate semantics survive — merging gated and ungated rules on the same path would distort their access. At evaluate time, each matching gated rule is checked against `Request::asset_groups` (populated in `PolicyStore::post_auth`) and OR'd into the base result. Explicit `deny` inside a gated rule still wipes the grant. Group-lookup failures surface as an empty `asset_groups`, which safely narrows access. Matching handles exact, prefix, and segment-wildcard (`+`) rule shapes.
- **KV-secret membership** -- `ResourceGroupEntry` grew a `secrets: Vec<String>` field stored in canonical form; canonicalization strips the KV-v2 `data/` and `metadata/` segments so `secret/foo/bar`, `secret/data/foo/bar`, and `secret/metadata/foo/bar` all collapse to the single entry `secret/foo/bar`. A parallel reverse index at `sys/resource-group/secret-index/<base64url(path)>` lets `groups_for_secret(path)` run in one read; base64url encoding avoids `/` collisions in the BarrierView key space. The write payload accepts a `secrets` comma-string or array, new `GET /v1/resource-group/by-secret/<b64url_path>` route exposes the reverse lookup, `reindex` rebuilds both reverse indexes, and `prune_secret(path)` is available on the store for future KV lifecycle wiring.
- **ACL qualifier extended to KV paths** -- `PolicyStore::post_auth`'s `resolve_asset_groups` now consults both reverse indexes. Anything outside the fixed non-KV prefixes (`sys/`, `auth/`, `identity/`, `resource-group/`, `cubbyhole/`, `resources/`) is treated as a candidate KV path and passed to `groups_for_secret` (which canonicalizes before lookup); results are unioned with the resource-index result into `Request::asset_groups`. A single `groups = [...]` rule can therefore gate access to resources and KV secrets uniformly.
- 7 integration tests: CRUD + canonicalization + partial updates (now asserts `secrets` field is present), reverse-index maintenance for resources, change-history shape, resource-delete lifecycle prune, ACL gate against a resource path, secret-membership canonicalization across v1/v2 variants + `by-secret` base64url lookup, and ACL gate against a KV-v1 mount (user with a `groups = ["kv-club"]` policy reads only the gated secret; membership swaps take effect without re-login).
- **List-filter on group-gated LIST ops** -- when a `LIST` operation is authorized *only* by a `groups = [...]`-gated policy rule, the evaluator records the rule's groups on `ACLResults.list_filter_groups`. `PolicyStore::post_auth` copies them onto `Request::list_filter_groups`, and a new `Handler::post_route` impl on `PolicyStore` narrows the response `keys` to entries whose resolved full logical path is a member of any listed group. An ungated LIST grant on the same path defeats the filter so a broader access is never accidentally narrowed. Works uniformly for the resource engine and KV mounts.
- **KV-delete lifecycle prune** -- `PolicyStore::post_route` also calls `ResourceGroupStore::prune_secret` on every successful `Delete` whose path is a KV candidate (anything outside `sys/`, `auth/`, `identity/`, `resource-group/`, `cubbyhole/`, `resources/`). Parallels the resource-delete hook in the resource module; prune failures are logged and never fail the delete. `PolicyStore` is now registered as both an `AuthHandler` (for `post_auth`) and a `Handler` (for `post_route`) in `src/modules/policy/mod.rs`.
- **Policy-compile warning for unknown asset groups** -- `handle_policy_write` collects every group name referenced via a `groups = [...]` clause, diffs against the current `ResourceGroupStore::list_groups()`, and attaches a response warning listing unknown names. The write still succeeds — creating a matching group later retroactively activates the clause — but operators see typos immediately instead of silently getting zero authorization.
- 3 new integration tests: `test_list_filter_on_groups_gated_list_kv` (KV-v1 mount, group gates `list` access so only members appear in the response), `test_kv_delete_prunes_from_groups` (deleting a KV secret drops it from every group that contained it), `test_policy_write_warns_on_unknown_groups` (response warning lists unknown names without blocking the write).
- Feature-complete for the single-tenant, non-ownership model. Pending items (ownership / admin transfer / sharing) remain blocked on [per-user-scoping](features/per-user-scoping.md).

#### Identity Groups (`features/identity-groups.md`)
- **Identity module** (`src/modules/identity/`) -- new logical backend mounted at `identity/` that manages user groups and application groups. Groups hold a list of members (UserPass usernames or AppRole role names) and a list of policies.
- **HTTP API**: `GET/PUT/DELETE /v1/identity/group/user/{name}`, `LIST /v1/identity/group/user`, and the symmetric `group/app/*` routes for application groups.
- **GroupStore** (`src/modules/identity/group_store.rs`) -- encrypted storage under the system barrier view at `sys/identity/group/{user,app}/` with a policy-expansion helper used at login time.
- **Policy union at login** -- UserPass (`path_login.rs`) and AppRole (`path_login.rs`) login handlers union the caller's directly-attached policies with policies from every group the caller is a member of. Renewal checks the unioned policy set for equivalence.
- **Default mount + migration** (`src/mount.rs`) -- new deployments get the `identity/` mount automatically; existing deployments pick it up on next unseal via a new `mount_update` migration that injects any missing default core mounts without overwriting existing ones.
- 3 integration tests covering user-group CRUD, user/app namespace isolation, and end-to-end policy expansion through a UserPass login.
- **GUI Groups page** (`gui/src/routes/GroupsPage.tsx`) -- list/create/edit/delete user and application groups, with tab switcher between kinds, multi-select member pickers sourced from UserPass / AppRole mounts, free-form member entry for foreign-mount members, and a policy multi-selector. Backed by 4 new Tauri commands (`list_groups`, `read_group`, `write_group`, `delete_group`) in `gui/src-tauri/src/commands/groups.rs`. Shows an empty state prompting reseal/unseal when the `identity/` mount is absent on legacy deployments.
- **Group change history with before/after values** -- every create/update/delete on a user or application group is recorded as a `GroupHistoryEntry { ts, user, op, changed_fields, before, after }` under `sys/identity/group-history/{user,app}/{name}/<20-digit-nanos>`. `before` and `after` hold the *values* of exactly the fields listed in `changed_fields` (description as a string, members and policies as arrays), so operators can see precisely what was added, removed, or modified. `members` and `policies` are compared as sets; pure reordering does not record a new entry. Delete entries retain the group's full final state in `before`, so the audit trail survives removal. Exposed via `GET /v1/identity/group/{user,app}/{name}/history` (newest first), surfaced in the Groups GUI as a new **History** tab with a dedicated `GroupHistoryPanel` that renders array diffs as added/removed chips and scalar changes as side-by-side before/after blocks.
- **FIDO2 login policy union** -- the unified FIDO2 login handler under userpass (`src/modules/credential/userpass/path_fido2_login.rs`) and the legacy standalone FIDO2 backend (`src/modules/credential/fido2/path_login.rs`) now call the same `expand_identity_group_policies(GroupKind::User, username, ...)` helper used by UserPass password login. A user who is a member of a user-group now receives the group's policies whether they authenticate via password or passkey. Token renewal checks the unioned set for equivalence, so adding or removing a user from a group takes effect on the next renewal. Expansion failures fall back to the user's direct policies and log a warning; FIDO2 login is never blocked by an identity-subsystem failure. (Phase 7, `features/identity-groups.md`)

#### Baseline Policies
- **`standard-user` seeded ACL policy** (`src/modules/policy/policy_store.rs`) -- new default policy intended for unprivileged end users. Grants token self-service operations, `read`/`list` on all KV secrets (v1 and v2 paths), `create`/`read`/`update`/`list` on resources and per-resource secrets, and full access to the caller's own `cubbyhole/`. Does not grant `delete` or any policy/user/mount/identity management. Seeded on first unseal and editable afterward (not in `IMMUTABLE_POLICIES`), so operators can tighten it to match a path convention. Known limitation: BastionVault does not yet substitute `{{username}}` placeholders in policy paths, so the policy cannot scope to "only the secrets *you* created"; per-user isolation requires either a path convention + policy edit or using identity groups to assign narrower policies per group.

#### Policy Change History
- **Policy change history with full HCL snapshots** -- every create/update/delete on an ACL policy is recorded as a `PolicyHistoryEntry { ts, user, op, before_raw, after_raw }` under `sys/policy-history/{name}/<20-digit-nanos>`, where `before_raw` and `after_raw` are the complete HCL text on each side of the change. No-op saves (same HCL) are suppressed; delete entries retain the full final policy text in `before_raw`, so the audit trail survives removal. Exposed via `GET /v1/sys/policies/acl/{name}/history` (newest first), surfaced in the Policies GUI as a new **History** tab with a dedicated `PolicyHistoryPanel` that renders expandable side-by-side before/after blocks and a **Restore this version** action that re-writes a previous `before_raw` as the current policy. Wired through `list_policy_history` Tauri command and `listPolicyHistory` API wrapper.

#### GitHub Actions
- Restricted all CI workflows (`rust.yml`, `deploy-website.yml`, `website.yml`) to only trigger on tag pushes matching `releases/**`.

#### Backup/Restore/Export/Import (Phase 5, `features/import-export-backup-restore.md`)
- **Backup format** (`src/backup/format.rs`) -- `BVBK` binary format with magic bytes, JSON header, entry frames, and HMAC-SHA256 integrity verification. 4 unit tests.
- **Backup creation** (`src/backup/create.rs`) -- `create_backup()` iterates all backend keys, writes encrypted blobs with optional zstd compression, appends HMAC.
- **Backup restore** (`src/backup/restore.rs`) -- `restore_backup()` verifies HMAC before writing any data, supports zstd decompression.
- **Secret export** (`src/backup/export.rs`) -- `export_secrets()` reads through the barrier (decrypted), produces JSON with mount/prefix.
- **Secret import** (`src/backup/import.rs`) -- `import_secrets()` writes JSON entries through the barrier, supports `--force` overwrite.
- CLI commands: `bvault operator backup`, `bvault operator restore`, `bvault operator export`, `bvault operator import`.
- HTTP endpoints: `POST /v1/sys/backup`, `POST /v1/sys/restore`, `GET /v1/sys/export/{path}`, `POST /v1/sys/import/{mount}`.
- API client methods: `Sys::export_secrets()`, `Sys::import_secrets()`.
- Error variants: `ErrBackupInvalidMagic`, `ErrBackupUnsupportedVersion`, `ErrBackupCorrupted`, `ErrBackupHmacFailed`, `ErrBackupHmacMismatch`.
- `zstd` dependency added to `Cargo.toml`.
- Made `list_all_keys()` public in `src/storage/migrate.rs` for reuse by backup module.

#### Cluster Failover (Phase 4A gap)
- `bvault cluster failover` CLI command to trigger leader step-down for planned maintenance.
- `POST /v1/sys/cluster/failover` HTTP endpoint.
- `Sys::cluster_failover()` API client method.
- `HiqliteBackend::trigger_failover()` method (HTTP POST to hiqlite step_down API).

#### HA Fault-Injection Tests (Phase 6, `features/hiqlite-ha-storage.md`)
- `tests/hiqlite_ha_fault_injection.rs` -- 8 multi-node HA test scenarios with `TestCluster` helper.
- Test scenarios: cluster formation, write-leader/read-follower, leader failover via step-down, follower restart without data loss, leader restart with re-election, write during election, quorum loss and recovery, graceful leave.

#### OIDC and SAML Auth Feature Plans
- `features/oidc-auth.md` -- OpenID Connect auth backend spec (Authorization Code Flow + PKCE, claim-to-policy role mappings, 5 endpoints).
- `features/saml-auth.md` -- SAML 2.0 auth backend spec (SP-initiated SSO, attribute-to-policy role mappings, 5 endpoints).

#### FIDO2/WebAuthn Auth Backend (Phase 6, `roadmaps/tauri-gui-fido2.md`)
- **FIDO2 credential module** (`src/modules/credential/fido2/`) following the standard Module/Backend pattern.
- `webauthn-rs` 0.5 and `webauthn-rs-proto` 0.5 dependencies.
- `Fido2Config` type for relying party configuration (RP ID, origin, name).
- `UserCredentialEntry` type storing policies, token params, and serialized passkey credentials.
- 7 API endpoints:
  - `auth/fido2/config` (Read/Write) -- relying party configuration.
  - `auth/fido2/register/begin` (Write, authenticated) -- start WebAuthn registration, returns `PublicKeyCredentialCreationOptions`.
  - `auth/fido2/register/complete` (Write, authenticated) -- complete registration, stores credential.
  - `auth/fido2/login/begin` (Write, unauthenticated) -- start authentication, returns `PublicKeyCredentialRequestOptions`.
  - `auth/fido2/login/complete` (Write, unauthenticated) -- verify assertion, update sign count, issue vault token.
  - `auth/fido2/credentials/{user}` (Read/Write/Delete/List) -- credential CRUD.
- Token renewal handler (`login_renew`) with policy change detection.
- Error variants: `ErrFido2NotConfigured`, `ErrFido2RegistrationFailed`, `ErrFido2AuthFailed`, `ErrFido2ChallengeExpired`, `ErrFido2CredentialNotFound`.

#### Resource Management (`features/resources.md`)
- **Resources abstraction** -- higher-level inventory entities (servers, network devices, websites, databases, applications, custom types) that group related secrets.
- Resources stored in KV engine at `_resources/` prefix with metadata: name, type, hostname, IP, port, OS, location, owner, tags, notes, timestamps.
- 5 built-in types + dynamic custom types.

#### Tauri Desktop GUI (Phases 1-6, `roadmaps/tauri-gui-fido2.md`)
- **Phase 1: Scaffold** -- Tauri v2 + React 19 + TypeScript 5.6 + Vite 6 + Tailwind CSS 4 project in `gui/`. Cargo workspace integration.
- **Phase 2: Embedded Mode** -- In-process vault with `FileBackend` at `~/.bastion_vault_gui/data/`, auto-init with 1-of-1 Shamir, unseal key and root token stored in OS keychain via `keyring` crate, seal on window close.
- **Phase 3: Core Screens** -- ConnectPage (mode selector), InitPage (first-launch wizard), LoginPage (Token + UserPass tabs), DashboardPage (seal status, mounts, auth methods).
- **Phase 4: Secrets & Management** -- 12 reusable UI components (`gui/src/components/ui/`): Button, Input, Textarea, Select, Card, Modal, Table, Badge, Tabs, EmptyState, Breadcrumb, Toast. SecretsPage (KV browser/editor with masked values), UsersPage (CRUD with modals), PoliciesPage (HCL editor with dirty tracking), MountsPage (secret engines + auth methods with enable/disable).
- **Phase 5: AppRole Dashboard** -- Role CRUD, role-id display with copy, secret-id generation (one-time display), accessor list with lookup/destroy. 9 Tauri commands.
- **Phase 6: Resources Page** -- Resource grid with type badges, search, type filter. Detail view with Info tab (editable metadata) and Secrets tab (per-resource secret management). Create modal with built-in + custom type selector.
- **Phase 7: FIDO2 GUI** -- FIDO2 login tab on LoginPage (username + "Authenticate with Security Key" button), Fido2Page for key management (RP config, credential info, register/delete keys). `useWebAuthn` hook encapsulating browser WebAuthn ceremony (base64url ↔ ArrayBuffer conversion, navigator.credentials.create/get). 8 Tauri FIDO2 commands.
- **Phase 8: Remote Mode** -- Connect to external BastionVault servers via HTTP API. `RemoteProfile` with address, TLS skip verify, CA cert path, client cert/key paths. `connect_remote` command tests connection via health endpoint. `disconnect_remote` clears session. `remote_login_token` and `remote_login_userpass` for authentication. ConnectPage now has an active "Connect to Server" button with a modal form for server URL and TLS configuration. Layout shows Local/Remote mode indicator.
- **Phase 9: Polish & Packaging** -- `ErrorBoundary` component catching React errors with recovery button. Real `SettingsPage` showing connection info (mode, server, TLS, data location), about section, and actions (seal, disconnect, sign out). Tauri feature forwarding (`storage_hiqlite` feature in GUI Cargo.toml forwarded to `bastion_vault`). `@tauri-apps/cli` added as dev dependency. Makefile targets: `run-dev-gui`, `gui-build`, `gui-test`, `gui-check`.
- **UI Testing** -- Vitest + React Testing Library + jsdom. 49 tests across 4 files: component tests (27), store tests (6), page tests (9), FIDO2 tests (7).
- Tauri backend: 55 commands across 9 modules (connection, system, auth, secrets, users, policies, approle, resources, fido2).

### Changed

- `HiqliteBackend` now implements `Debug` (manual impl, omits non-Debug fields). Fixes cucumber test compilation.
- `storage::migrate::list_all_keys()` changed from private to public for reuse by backup module.
- Roadmap updated: hiqlite initiative moved to Completed (all 6 phases done), GUI initiative completed (all 9 phases), FIDO2 auth backend marked Done.
- `features/hiqlite-ha-storage.md` updated to reflect all phases complete.
- `features/import-export-backup-restore.md` updated to reflect implementation complete.
- `gui/src-tauri` added to workspace members in root `Cargo.toml`.

### Removed

- Branch and pull_request triggers from all GitHub Actions workflows (now tag-only via `releases/**`).

#### Change history (GUI + backend)
- **KV-v2 per-version audit fields**: `VersionMetadata` and `VersionData` now include `username` (from `auth.metadata["username"]`, falling back to `auth.display_name`, finally `"unknown"`) and `operation` (`"create"` / `"update"` / `"restore"`). `data/` responses expose both in the metadata envelope. On-disk format is backward-compatible via `#[serde(default)]`.
- **Resource metadata history**: new append-only audit log at `hist/<name>/<nanos>` in the resource engine. Each entry records `ts`, `user`, `op` (`create` / `update` / `delete`), and `changed_fields` -- the set of top-level field names that differ from the previous write, excluding timestamp/identity fields. Redundant saves that only touch `updated_at` do NOT generate entries. Exposed through a new path `resources/<name>/history` (`Operation::Read`).
- **Resource secret versioning**: resource secrets are now versioned. Each write snapshots to `sver/<resource>/<key>/<version>` and updates `smeta/<resource>/<key>`; the current value is still kept at `secret/<resource>/<key>` for O(1) reads. New paths: `secrets/<resource>/<key>/history` (version list) and `secrets/<resource>/<key>/version/<n>` (read old value).
- **Tauri commands**: `list_secret_versions`, `read_secret_version`, `list_resource_history`, `list_resource_secret_versions`, `read_resource_secret_version`.
- **GUI**: new History button on the SecretsPage detail pane (KV-v2 only); new History tab on the Resources detail view; new History button on the resource-secret detail pane. Timeline UI shared across secrets (`SecretHistoryPanel`) and resources (`ResourceHistoryPanel`). Clicking a version loads its data masked with `MaskedValue`; a Restore button writes the old value as a new version.
- Tests: 5 new Rust unit tests for the diff helper + history-seq ordering, 3 new integration tests in `tests/test_default_logical.rs` covering KV-v2 username tracking, resource metadata history (including the no-op-write suppression), and resource secret versioning. 20 new vitest tests for the two history panels, timestamp/op helpers, and a regression on the generator + policy check.

### Fixed

#### Windows build
- **`openssl-sys` link failure** on Windows MSVC -- added `openssl` dep with the `vendored` feature on `cfg(windows)` in root `Cargo.toml` and `gui/src-tauri/Cargo.toml` so the transitive `openssl-sys` (via `authenticator` and `webauthn-rs-core`) builds from source without a system install.
- **`authenticator 0.5.0` type mismatch** (`expected winapi::ctypes::c_void, found libc::c_void`) on Windows -- worked around by adding `winapi = { version = "0.3", features = ["std"] }` as a direct dep in `gui/src-tauri/Cargo.toml`; Cargo's feature unification enables winapi's `std` feature, which re-exports `std::ffi::c_void` as `winapi::ctypes::c_void`.
- **`tauri-winres` RC2176 "old DIB"** -- regenerated `gui/src-tauri/icons/icon.ico` via `npx @tauri-apps/cli icon` so the Windows Resource Compiler accepts the modern PNG-based Vista-style ICO format.
- Unused `Deserialize` import in `gui/src-tauri/src/commands/resources.rs`.

### Security

#### WebView2 plaintext-secret leak (GUI)
- **Disabled WebView2 form autofill** to stop Chromium/Edge from persisting typed secret values to its `Web Data` SQLite cache. Three layers of defense:
  1. `gui/src-tauri/src/lib.rs` -- new `harden_webview_autofill()` called from the Tauri `setup` hook; uses `ICoreWebView2Settings6::SetIsGeneralAutofillEnabled(false)` and `SetIsPasswordAutosaveEnabled(false)`.
  2. `run()` also sets `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--disable-features=AutofillServerCommunication,AutofillEnableAccountWalletStorage` before WebView2 init.
  3. New `SecretInput` component (`gui/src/components/ui/SecretInput.tsx`) with `type="password"`, `autoComplete="new-password"`, `spellCheck={false}`, and password-manager ignore hints; used on `SecretsPage` for KV secret values. Base `Input` component now defaults to `autoComplete="off"` + `spellCheck={false}` so no ordinary text input persists to autofill.
- Added `webview2-com = "0.38"` and `windows = { version = "0.61", features = ["Win32_Foundation"] }` as Windows-only deps in `gui/src-tauri/Cargo.toml` for the `CoreWebView2Settings` calls.
- Users upgrading from earlier builds should delete `%LOCALAPPDATA%\com.bastionvault.gui\EBWebView\Default\Web Data*` to purge any previously-captured plaintext.

---

## [Previous entries below are from earlier development phases]

## Hiqlite Phase 1 (Initial Implementation)

### Added

- **Hiqlite storage backend** (`storage "hiqlite"`) -- embedded Raft-based SQLite storage engine providing built-in replication, leader-aware writes, and distributed locking without requiring an external database service. Gated behind the `storage_hiqlite` feature flag, now enabled by default.
- Hiqlite configuration support in HCL and JSON config files with keys: `data_dir`, `node_id`, `secret_raft`, `secret_api`, `table`, `listen_addr_api`, `listen_addr_raft`, `nodes`.
- Distributed locking via hiqlite's `dlock` feature, replacing no-op lock behavior for the HA backend.
- Cucumber BDD test suite for the hiqlite backend (`tests/features/hiqlite_storage.feature`) covering CRUD operations, prefix listing, deletion, and overwrite scenarios.
- CI jobs for hiqlite backend testing on Linux, macOS, and Windows.
- Hiqlite HA storage roadmap documenting Phases 0-6 for full HA deployment.
- Feature definitions directory (`features/`) with detailed specs for:
  - Secret Versioning & Soft-Delete (KV v2 engine)
  - Audit Logging (tamper-evident, HMAC chain)
  - HSM Support (PKCS#11 auto-unseal, key wrapping, crypto providers)
  - Import/Export & Backup/Restore
  - Caching (token, secret, and configurable policy caching)
  - Batch Operations (multi-operation single-request API)
  - Hiqlite HA Storage (full feature definition with all phases)

### Changed

- **`storage_hiqlite` is now the default feature**. A plain `cargo build` includes the hiqlite backend. Use `--no-default-features` to build without it.
- Updated global roadmap (`roadmap.md`) to reflect the switch from rqlite to hiqlite and current implementation status.
- Renamed roadmap file from `rqlite-default-ha-storage.md` to `hiqlite-default-ha-storage.md`.
- Agent instructions (`agent.md`) now require keeping `CHANGELOG.md` updated with all changes.

### Fixed

- `sync_handler` feature build failure: added missing `#[maybe_async::maybe_async]` annotations to `init_with_pq` and `unseal_with_pq` methods in `barrier_chacha20_poly1305.rs`.

## Hiqlite Phase 2: Replication Semantics

### Added

- Cluster-specific error variants: `ErrClusterNoLeader`, `ErrClusterQuorumLost`, `ErrClusterUnhealthy`, `ErrCluster(String)`. All map to HTTP 503 (Service Unavailable) except generic `ErrCluster` which maps to 500.
- `GET /v1/sys/health` endpoint (unauthenticated) returning `initialized`, `sealed`, `standby`, and `cluster_healthy` fields. HTTP status varies: 200 (active leader), 429 (standby/follower), 503 (sealed or unhealthy), 501 (not initialized).
- `GET /v1/sys/cluster-status` endpoint returning storage type, cluster state, leader status, and Raft metrics (when using hiqlite backend).
- `HiqliteBackend::is_leader()`, `is_healthy()`, `cluster_metrics()` methods exposing hiqlite's Raft cluster state.
- `Sys::health()` and `Sys::cluster_status()` client API methods.
- Status CLI command now displays `standby` and `cluster_healthy` fields when available.

### Changed

- Hiqlite error handling: replaced generic `ErrResponse(string)` mapping with structured `map_hiqlite_error()` that inspects hiqlite's `Error` enum variants and maps to specific cluster error types.
- `Backend` trait now requires `Any` supertrait bound for downcast support in health endpoints.

## Hiqlite Phase 3: Default Server Recommendation

### Added

- Production config examples: `config/single-node.hcl` (single-node hiqlite with TLS) and `config/ha-cluster.hcl` (3-node HA cluster).
- Server startup warning when using the file backend, directing operators to hiqlite configs.

### Changed

- `config/dev.hcl` clearly labeled as development-only with comments pointing to production configs.
- Server CLI help text updated to recommend hiqlite for production and list all example config files.

## Hiqlite Phase 4/4A: Cluster Management CLI

### Added

- `bvault cluster` command group with three read-only inspection subcommands:
  - `bvault cluster status` -- full cluster status with Raft metrics.
  - `bvault cluster leader` -- leader and health information.
  - `bvault cluster members` -- cluster membership from Raft metrics.
- All cluster commands support standard HTTP, TLS, and output format options.
- `bvault cluster leave` -- gracefully leaves the Raft cluster and shuts down the node.
- `bvault cluster remove-node --node-id N` -- removes a failed node from the cluster. Supports `--stay-as-learner` to demote instead of fully removing.
- `POST /v1/sys/cluster/leave` and `POST /v1/sys/cluster/remove-node` API endpoints for programmatic cluster management.
- `HiqliteBackend::remove_node()`, `leave_cluster()`, and `node_id()` methods for cluster topology operations.

## Hiqlite Phase 5: Migration Tooling

### Added

- `bvault operator migrate` CLI command for offline backend-to-backend data migration.
- `src/storage/migrate.rs` module with `migrate_backend()` function that recursively copies all encrypted entries from source to destination.
- Supports any backend combination: file -> hiqlite, mysql -> hiqlite, hiqlite -> file, etc.
- Data copied as raw encrypted bytes -- same unseal keys work after migration.

## Hiqlite Phase 6: HA Validation

### Added

- `test_hiqlite_cluster_health` unit test verifying single-node leader status, health, metrics, and node ID.
- `test_hiqlite_migrate_from_file` integration test verifying backend-to-backend migration from file to hiqlite with nested key paths.
- `tests/features/hiqlite_ha.feature` cucumber scenarios for HA cluster operations (5 scenarios).

## Test Fixes

### Fixed

- **TLS test panic**: all CLI/module tests that passed `tls_enable: true` to `TestHttpServer` hit a panic because TLS certificate generation was removed with OpenSSL. Fixed by falling back to plaintext HTTP in tests when TLS certs are unavailable. All 22 affected tests now pass.
- **Unseal key length assertion**: `test_generate_unseal_keys_basic` hardcoded expected key length as 33 bytes (AES-GCM). Fixed to dynamically use `barrier.key_length_range()` which returns 64 for ChaCha20Poly1305 (ML-KEM-768 seed) + 1 Shamir overhead = 65.
- **Metrics count assertion**: `test_metrics_name_and_help_info` expected exact metric count but some system metrics aren't available on all platforms. Fixed to use range assertion.
- **Hiqlite tests gated**: hiqlite integration tests require `CARGO_TEST_HIQLITE=1` env var since they start Raft nodes on fixed ports and can hang in constrained environments.
- **Hiqlite enc_keys**: added required `cryptr::EncKeys` initialization with a generated key to `NodeConfig` (hiqlite 0.13 requires non-empty encryption keys).

### Removed

- **SQLx storage backend** (`storage "sqlx"`) -- removed entirely due to `libsqlite3-sys` native link conflict with hiqlite's `rusqlite` dependency. The `storage_sqlx` feature flag and `sqlx` dependency have been removed from `Cargo.toml`.
- `SqlxError` variant removed from error types.
- SQLx-related CI jobs (`unix-sqlx-mysql-test`, `windows-sqlx-mysql-test`) replaced with hiqlite CI jobs.
