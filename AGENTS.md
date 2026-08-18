# Agent Guide

**Authoritative instruction file for AI coding agents (Codex, Claude Code, others).**
`CLAUDE.md` and `agent.md` are pointers to this file — do not duplicate rules there.

BastionVault: Rust secrets-management server, HashiCorp Vault API-compatible.
Identity-based access control, encrypted storage, post-quantum crypto, Tauri desktop GUI.
Security-sensitive code: correctness, reviewability and operational safety outrank speed
and cleverness.

---

## 1. Default loop

```
read this file → find component in §2 → inspect that dir + its direct deps only
→ make one coherent change → L1 check (§4) → L2 component tests (§4)
→ L3 `make test-changed` once, at the end (§4) → L4 only for a release
```

`make test-changed` works the dependents out from the dependency graph, so you
do not have to. `make test` (the whole workspace) is a release-gate cost, not an
inner-loop one — see §4.

Never: scan the repo → full build → edit → full build. Never run two `cargo`
commands at the same time (§5).

---

## 2. Architecture map

Dependency direction is strictly upward. The tier numbers are historical, not
an ordering — the real chain is 0 → 1 → 3 (engines) → 2 (`bv-core` →
`bv-kernel` → the `bastion_vault` facade) → 4. A crate never depends on a
higher tier. `cargo check -p <pkg>` compiles only that crate and what is below
it.

### Tier 0 — substrate (`crates/`)

| Package | Path | Purpose | Depends on |
|---|---|---|---|
| `bv-errors` | `crates/bv-errors` | `RvError`, the shared error type | — |
| `bv_crypto` | `crates/bv_crypto` | ML-KEM-768 / ML-DSA-{44,65,87}, AEAD primitives | — |
| `bv-metrics` | `crates/bv-metrics` | Prometheus families + registry | — |
| `bv_plugin_surface` | `crates/bv_plugin_surface` | Plugin ABI types shared host↔plugin | — |
| `bv-context` | `crates/bv-context` | Task/cancellation context | `bv-errors` |
| `bv-shamir` | `crates/bv-shamir` | Shamir secret sharing (unseal keys) | `bv-errors` |
| `bv-storage` | `crates/bv-storage` | Barriers, physical backends (file/hiqlite/mysql/cloud), read caches | `bv-errors` `bv-metrics` `bv_crypto` |
| `bv-logical` | `crates/bv-logical` | `Request`/`Response`/`Backend`/`Path`/`Field` + `Handler` | `bv-context` `bv-errors` `bv-storage` |
| `bv-audit` | `crates/bv-audit` | Audit entries, hash chain, file device, broker fan-out | `bv-errors` `bv-logical` `bv-storage` |
| `bv-utils` | `crates/bv-utils` | Salts, seal boxes, socket addrs, TLS/cert helpers | `bv-errors` `bv-logical` `bv-shamir` `bv-storage` `bv_crypto` |

### Tier 1 — kernel contract

| Package | Path | Purpose | Depends on |
|---|---|---|---|
| `bv-kernel-api` | `crates/bv-kernel-api` | The contract every engine compiles against: `VaultCtx`, `KernelServices`, `Module`, routing/mount tables | `bv-errors` `bv-logical` `bv-storage` `bv-audit` `bv-utils` |

Editing this crate rebuilds every engine and everything above. Treat as high blast radius.

### Tier 3 — engines and auth backends

Each is `bv-kernel-api` + Tier 0 + its own domain deps, and **nothing else** —
except the auth backends, five of which depend on `bv-auth-audit` (the shared
login-audit store) and two on a sibling backend. Unit tests are in-crate
`#[cfg(test)]`. Test with `cargo nextest run -p <pkg> --lib`.

| Package (`crates/…`) | Domain |
|---|---|
| `bv-engine-pki` | PKI / X.509 / CRL / ACME (largest engine, ~15k lines) |
| `bv-engine-transit` | Encryption-as-a-service, key versions, BYOK |
| `bv-engine-kv` | KV secret engine |
| `bv-engine-ssh` | SSH CA + OTP certs |
| `bv-engine-ssh-broker` | SSH session brokering |
| `bv-engine-totp` | TOTP |
| `bv-engine-ldap` | LDAP secret engine |
| `bv-engine-files` | Encrypted file resources + sync transports (SMB/SFTP/SCP) |
| `bv-engine-notifications` | Notification delivery |
| `bv-engine-resource` | Generic resources |
| `bv-engine-rustion` | Rustion bastion integration (~10k lines) |
| `bv-engine-cert-lifecycle` | Certificate lifecycle scheduler |
| `bv-auth-audit` | Shared auth audit store |
| `bv-auth-approle` | AppRole |
| `bv-auth-userpass` | UserPass (+ FIDO2 step-up) |
| `bv-auth-cert` | TLS client-cert auth |
| `bv-auth-fido2` | FIDO2 / WebAuthn RP |
| `bv-auth-ferrogate` | FerroGate machine auth (DPoP, composite Ed25519+ML-DSA-65) |
| `bv-auth-saml` | SAML |
| `bv-auth-oidc` | OIDC |

### Tier 2 — kernel tier: `bv-core`, `bv-kernel`, the `bastion_vault` facade

Split in three by Phase 4.5. `bv-kernel` sits **above** `bv-core`: `Core` is the
substrate the six kernel modules are built on, not their caller, and the eight
edges that pointed the other way go through contracts in
`bv_kernel_api::pipeline` / `::auth`. Do not re-derive that — the roadmap's
Phase 4.5 section records it.

| Package | Path | Purpose | Depends on |
|---|---|---|---|
| `bv-core` | `crates/bv-core` | Tier 2a, 6.4k lines. `Core`, mount table, module registry, `KernelServices` impl, seal path, HSM, config, logging | `bv-errors` `bv-logical` `bv-storage` `bv-audit` `bv-utils` `bv-shamir` `bv_crypto` `bv-kernel-api` |
| `bv-kernel` | `crates/bv-kernel` | Tier 2b, 32k lines. The six kernel modules — the bulk of what the root crate used to be | `bv-core` `bv-kernel-api` + Tier 0 + `bv-auth-audit` `bv-auth-userpass` `bv-engine-files` `bv-engine-ssh` (audit stores + the userpass record) |
| `bastion_vault` | `src/`, 28k lines (16k production) | The facade: mount list, plugin runtime, backup/exchange/exports, in-process API, and the tests that could not travel | `bv-core` `bv-kernel` + every engine and auth crate |

An edit anywhere in this tier rebuilds `bv-server`, `bvault-cli` and the GUI.
`bv-core` also rebuilds `bv-kernel` and the facade; the facade rebuilds nothing
below it.

#### `bv-core` — `crates/bv-core/src/`

| Path | Responsibility |
|---|---|
| `core.rs`, `mount.rs`, `module_manager.rs`, `kernel_impl.rs` | Vault core, mount table, module registry, `KernelServices` impl |
| `seal/` | Seal/unseal, incl. the HSM-backed seal (`seal/hsm.rs`) |
| `hsm/` | HSM backends (`hsm_mock`, `hsm_yubihsm2`), enroll, custody, replicate, derive |
| `config.rs`, `logging.rs`, `server_info.rs` | HCL config, logging, server identity |

The `hsm_mock` / `hsm_yubihsm2` features live here and are forwarded
`bvault-cli` → `bastion_vault` → `bv-core`. Nothing else in the workspace
compiles them — verify a feature change with `make check-hsm` (§4), not by
reading the manifest.

#### `bv-kernel` — `crates/bv-kernel/src/modules/`

| Path | Responsibility |
|---|---|
| `auth/` | Token store, lease/expiration manager |
| `identity/` | Entities, groups, aliases |
| `policy/` | Policy store + evaluation (largest kernel module) |
| `namespace/` | Namespaces / multi-tenancy |
| `resource_group/` | Resource groups |
| `system/` | `sys/` backend: mounts, seal, remount, health |
| `credential/` | The two-entry subset of the facade's credential list the kernel itself reads |
| `crypto/` | Retired placeholder; the crypto is `bv_crypto` |

#### `bastion_vault` — `src/`

| Path | Responsibility |
|---|---|
| `src/lib.rs`, `src/modules/` | The facade itself: re-exports `bv-core` and `bv-kernel` under the paths they have always had, plus the full engine mount list |
| `src/plugins/` | WASM (wasmtime) + process plugin runtime, catalog, grants, verifier, quarantine |
| `src/backup/`, `src/exchange/`, `src/scheduled_exports/` | BVBK backup, `.bvx` import/export, cron exports |
| `src/api/` | In-process client API |
| `src/audit/` | `sys_emit` glue above `bv-audit` |
| `src/dos/`, `src/metrics/` | DoS store + metrics registry glue (middleware lives in `bv-server`) |
| `src/test_utils.rs` | `new_test_bastion_vault`, seal helpers, `test_*_api` (feature `test-support`) |
| `src/engine_tests/` | Engine tests that need `test_utils` and therefore cannot live in the engine crate |
| `src/core_tests.rs`, `src/storage_backend_tests.rs` | `Core` and storage-backend tests, here for the same reason |

### Tier 4 — assembly

| Package | Path | Purpose | Depends on |
|---|---|---|---|
| `bv-server` | `crates/bv-server` | actix-web HTTP surface: routes (`logical_routes`, `sys`, `batch`, `metrics_routes`, `rustion_webhook`), middleware (dos, metrics), proxy-protocol, client-IP | `bastion_vault` `bv-metrics` `bv_plugin_surface` |
| `bvault-cli` | `crates/bvault-cli` | The `bvault` binary + deb/rpm/msi packaging metadata | `bastion_vault` `bv-server` `bv-client` |
| `bastion-vault-gui` | `gui/src-tauri` | Tauri v2 host (embedded vault mode) | `bastion_vault` |
| `bv-client` | `crates/bv-client` | HTTP `RemoteBackend`, SRV cluster discovery, health | `bv_plugin_surface` |
| `bastion-plugin-sdk` | `crates/bastion-plugin-sdk` | Plugin author SDK | `bv_plugin_surface` |
| `bastion-plugin-testkit` | `crates/bastion-plugin-testkit` | Mock host + ABI conformance suite | — |
| `bv_plugin_manifest` | `crates/bv-plugin-manifest` | `plugin.toml` parsing (note: package name uses `_`) | `bv_plugin_surface` |
| `bv-plugin-pack` | `crates/bv-plugin-pack` | `.bvplugin` packer/signer (bin only) | `bv_crypto` `bv_plugin_manifest` |

GUI frontend: `gui/src/` (React 19 + TS + Tailwind 4), tests co-located as `*.test.tsx`.

Note: two deliberate dev-only cycles. `bastion_vault` **dev**-depends on
`bv-server` so the ~50 tests that drive a real HTTP server can stay in the root
crate, and `bv-kernel` **dev**-depends on `bastion_vault` so its ~200 tests can
reach `test_utils`. A dev-dependency cycle is fine for fixtures used as values
and **unsound** for anything resolved by `TypeId`, `Any::downcast` or a
type-keyed registry — that is why 25 kernel tests live in `src/engine_tests/`
instead. See the roadmap's Phase 4.5 section.

### Reference docs — read instead of re-deriving

| Doc | Use for |
|---|---|
| `roadmaps/workspace-decomposition.md` | Why the tiers exist, what each phase moved, measured deltas. Every phase (0–6, incl. 4.5, the Tier 2 split) is done; what is left is cutting the first release by hand. |
| `.config/nextest.toml` | Which suites are excluded from nextest and why (read before touching test scope) |
| `scripts/ci-plan.sh`, `.github/workflows/tests.yml` | What CI runs and how it decides — read before changing test scope or cache keys |
| `docs/publishing-crates.md`, `scripts/crates-plan.sh` | Per-crate versions and the Cloudsmith release loop — read before touching any `version` field |
| `docs/build-timings/baseline.md` | Build-cost baseline, noise floor, how to get comparable numbers |
| `roadmap.md`, `features/*.md`, `roadmaps/*.md` | Feature status and specs |
| `docs/api.md`, `docs/cli-reference.md`, `docs/configuration.md` | Operator-facing surfaces |

---

## 3. Blast radius

| You edited | Check | Test | Then |
|---|---|---|---|
| One engine/auth crate | `cargo check -p <pkg>` | `cargo nextest run -p <pkg> --lib` | Root only if its public API changed |
| `bv-kernel-api` | `cargo check -p bv-kernel-api` | one dependent engine | `cargo check --lib`, then L3 |
| `bv-storage` / `bv-logical` / `bv-utils` / `bv-audit` | `cargo check -p <pkg>` | `cargo nextest run -p <pkg> --lib` | one engine, then `cargo check --lib` |
| `crates/bv-core` | `cargo check -p bv-core` | `cargo nextest run -p bv-core --lib` | `cargo check -p bv-kernel --lib`, then L3 — it rebuilds the whole tier |
| `crates/bv-core/src/hsm/` | `make check-hsm` | `cargo nextest run -p bv-core --lib` | nothing else compiles these — see L4 |
| `crates/bv-kernel` | `cargo check -p bv-kernel` | `cargo nextest run -p bv-kernel --lib` | `cargo check --lib`, then `-p bv-server -p bvault-cli` |
| `src/` (the facade) | `cargo check --lib` | `cargo nextest run -p bastion_vault --lib` | `cargo check -p bv-server -p bvault-cli` |
| `crates/bv-server` | `cargo check -p bv-server` | `cargo nextest run -p bv-server --lib` | nothing above it |
| `crates/bvault-cli` | `cargo check -p bvault-cli` | `make test-bin` then CLI tests | nothing above it |
| `gui/src/` | `cd gui && npx tsc --noEmit` | `npx vitest run <file>` | — |
| `gui/src-tauri/` | `cargo check -p bastion-vault-gui` | — | — |

The "Then" column is the same reverse-dependency walk `make test-changed`
performs from the cargo graph. Use it as the check that you got the radius
right — `make test-plan` prints the set without building anything. Measured
widths today (of 41 packages `test-plan` considers): one engine → 5,
`bv-kernel` or the facade → 4, `bv-core` → 5, `bv-kernel-api` → 26, `bv-errors`
→ 33.

---

## 4. Validation levels

### L1 — fast, while editing (seconds on a warm tree)

```bash
cargo check -p bv-engine-pki          # front-end only, one crate
cargo fmt -p bv-engine-pki
cargo clippy -p bv-engine-pki --lib   # never --all-features (see §5)
cargo check --lib                     # root crate only; NOT --workspace
```

### L2 — component, when a coherent change is done

```bash
cargo nextest run -p bv-engine-pki --lib             # one crate's unit tests
cargo nextest run -p bv-engine-pki --lib issue_cert  # substring filter
cargo nextest run -E 'test(test_issue_cert)'         # nextest expression, whole workspace
cargo test -p bv-engine-pki --lib test_issue -- --nocapture   # when you need stdout
cargo test -p bv-utils --doc                         # doctests for one crate
cargo nextest run -p bastion_vault --test test_pki_engine     # ONE integration binary
```

### L3 — affected packages, before handing the change off

```bash
make test-plan       # which packages would run — no build, costs nothing
make test-changed    # run them
```

`test-changed` derives the set from `git diff` + the cargo dependency graph
(reverse deps, dev-dependencies included) and runs `cargo nextest run -p ...
--lib` over just that. It is the correct default at this level: `make test`
links ~44 test harnesses, five of them 200 MB+, and a one-engine change reaches
5 of 41 packages.

```bash
make test-changed BASE=main         # + everything committed since merge-base(main)
make test-changed DIRECT=1          # changed packages only, skip dependents
make test-changed PKG=bv-engine-pki # explicit seed, ignore git
make test-changed FILTER=issue_cert # pass a filter through to nextest
```

If the affected set reaches `bastion_vault`, `bv-server` or `bvault-cli`,
`test-changed` builds `target/debug/bvault` first and says so — those packages'
lib tests spawn the real executable rather than driving the CLI in-process, and
building a test harness does not produce it. That link is the largest single
cost of a narrow run that reaches it: a minute or two before the first test
runs, then a few seconds' freshness check on every run after. It is not
optional — without it five `cli::command::*` tests fail with `No such file or
directory (os error 2)`, or pass against a stale binary. `make test-plan` shows
whether your run pays it, and `make test-bin` is the same build on its own.

Read the header of `scripts/test-changed.sh` before trusting an unexpected
result. Two behaviours matter: editing `Cargo.toml`, `Cargo.lock`,
`.cargo/config.toml`, `rust-toolchain.toml` or `.config/nextest.toml` forces a
full run (they change what the whole workspace compiles against), and `tests/`,
doctests and the GUI are reported but **not** run.

`make test` remains correct, and is what CI collapses to when a change reaches
most of the workspace — use it when `test-changed` says the affected set is that
wide, or when you want the bins covered too.

### L4 — everything, before a release or a high-risk merge

```bash
make test-release   # every suite in the repo, in order (tens of minutes)
```

Required before cutting a release, and before merging anything that touches a
persisted format, a storage barrier, authn/authz, or the plugin ABI. Runs
`test`, `test-integration`, `test-doc`, `test-hiqlite`, `test-cucumber`,
`plugins-test`, `gui-check`, `gui-test` and `check-hsm DEEP=1`. Only
`tests/e2e/rustion-ssh` is left out — it needs real remote hosts.

The pieces, when you want one of them on its own:

```bash
make test-integration   # tests/: ~30 binaries, each links the full graph + a 245 MB rlib
make test-hiqlite       # port-bound, single process, CARGO_TEST_HIQLITE=1
make test-cucumber      # harness = false, fixed ports 28100/28200
make plugins-test       # testkit + host ABI parity + plugin substrate
make check-hsm          # the HSM seal backends; DEEP=1 for the container image's own graph
make test-all           # test + test-integration + test-doc
make build              # release build
```

`check-hsm` is the only thing in this file that compiles `hsm_mock` /
`hsm_yubihsm2`. They are off in every default build and `--all-features` is
banned (§5), so `cargo check --workspace`, `check-isolated` and every test
target compile *around* the seal backends rather than through them — the first
build to notice a break was the container image, minutes into a cross-compile,
twice. It stops at `bv-core` (every `#[cfg(feature = "hsm_*")]` site in the
workspace is there) and walks the feature chain above it from `cargo metadata`,
so the cheap form costs ~35 s. Run it after touching anything under
`crates/bv-core/src/hsm/`, `bv-core`'s manifest, or the feature declarations
that pass the flags down.

CI (`.github/workflows/tests.yml`) runs **everything except
`tests/e2e/rustion-ssh`** — unit, doctests, `tests/`, hiqlite, cucumber, the
per-crate isolation check, the HSM seal backends, and the GUI. A push to `main`
runs the lot; a pull request runs only the packages the change can reach,
derived from the same
`cargo metadata` graph `make test-changed` uses. `make ci-plan` prints that plan
locally without building anything:

```bash
make ci-plan BASE=main          # what CI will do with this branch
make ci-plan PKG=bv-engine-pki  # what it would do if you touched that crate
make check-isolated             # cargo check every member on its own
make check-hsm                  # the seal backends, which no other build compiles
```

Do not weaken it, and do not reproduce it locally after every edit — that is
what §4's L1–L3 are for.

### Test locations

| Kind | Location | Command |
|---|---|---|
| Unit | in-crate `#[cfg(test)]` | `cargo nextest run -p <pkg> --lib` |
| Tests needing `test_utils` (engines, `Core`, 25 kernel tests) | `src/engine_tests/`, `src/core_tests.rs` | part of `-p bastion_vault --lib` |
| Integration (~30 bins) | `tests/test_*.rs` | `--test <name>` for one; `make test-integration` for all |
| Standalone crate tests | `crates/bv-client/tests`, `crates/bv_crypto/tests` | `cargo nextest run -p bv-client` |
| Cucumber | `tests/features/*.feature`, `tests/cucumber_hiqlite.rs` | `make test-cucumber` |
| HA / hiqlite (port-bound) | `bv-storage` `hiqlite::test::`, `tests/hiqlite_ha_fault_injection.rs` | `make test-hiqlite` |
| Plugin ABI parity | `tests/test_plugin_testkit_parity.rs` | `make plugins-test` |
| GUI | `gui/src/**/*.test.tsx` | `cd gui && npx vitest run [file]` |
| E2E (manual, needs real hosts) | `tests/e2e/rustion-ssh` | not part of any suite |

---

## 5. Build hygiene — this is where the wall-clock time actually goes

**One cargo invocation at a time.** All cargo commands share one `target/` build
lock. Two concurrent invocations do not run in parallel — the second blocks for
as long as the first takes. Measured on this tree: a `cargo check -p bv-errors`
that should cost <1 s took **9m 14s wall with 0.4 s of CPU** because a
concurrent `cargo test` and `cargo clippy --all-targets --all-features` held the
lock. Parallelize *searching and reading*; serialize *building*.

The Makefile declares `.NOTPARALLEL`, so `make -j` cannot overlap two recipes.
That covers make; it cannot stop you from running a second cargo in another
terminal, a background shell, or a parallel agent session. Do not. If a run is
mysteriously slow, look for `Blocking waiting for file lock on build directory`
in its output and check `pgrep -lf '/cargo '` — `make test-changed` warns about
this on its own.

rust-analyzer is the one exception, and only because it is configured to be:
`.vscode/settings.json` sets `rust-analyzer.cargo.targetDir`, so its on-save
`cargo check --workspace --all-targets` writes to `target/rust-analyzer` and
holds a different lock. Do not remove that setting to save disk — without it,
every file save can stall a test run for minutes.

**Never `--all-features` or casual `--all-targets`.** `--all-features` turns on
`hsm_yubihsm2` (vendored libusb C build), `storage_mysql`, every cloud target
and every PQC preview at once. It materializes a second feature-variant of a
1200-crate graph in `target/` and is one of the slowest commands available here.

**Never `--workspace` for a check.** It drags in `gui/src-tauri` (Tauri + wry +
webview). Use `cargo check -p <pkg>` or `cargo check --lib`.

**Never clean.** No `cargo clean`, no `make clean`, no `make deep-clean`, no
deleting `target/` — a cold build of this tree (aws-lc-rs, vendored openssl,
russh, hiqlite, wasmtime) is tens of minutes. `make prune` (drops
`target/*/incremental` only) is the sanctioned reclaim; it costs one slower
rebuild. `make prune-stale` (KEEP=3 sessions per crate) already runs
automatically before every compiling `make` target.

**Watch the disk.** `target/` was measured at **394 GB** (227 GB
`debug/incremental`, 162 GB `debug/deps`) on a 954 GB volume. Run
`make target-size` when builds feel slow for no reason; propose `make prune` to
the user rather than deleting anything yourself.

**Profile is already tuned** (root `Cargo.toml`): `debug = "line-tables-only"`,
`split-debuginfo = "unpacked"`, no debug info for build scripts. Do not
"optimize" it again. `-Z threads` is wired into `make build` / `make run-dev*`
only, on purpose — those RUSTFLAGS key a separate artefact set, so do not add
them to check/test commands.

**Measuring build cost:** `make bench-build-quick` (nothing logged) or
`make bench-build` (median of 3, appends a row). Read
`docs/build-timings/baseline.md` first — the noise floor is ~25 %, and the
harness needs a settled `target/` to give comparable numbers.

`cargo-nextest` is required by every `make test*` target
(`cargo install --locked cargo-nextest`, >= 0.9.84).

---

## 6. Do not inspect, index or build

```
target/  target-plugin-pack/  node_modules/  gui/node_modules/  gui/dist/
docs/build-timings/*.html  .git/
third_party/  IronRDP/  plugins-ext/     # separate Cargo workspaces / submodules
```

`plugins-ext/`, `IronRDP/` and `third_party/hiqlite` are excluded from the
workspace on purpose. Build them only through their `make plugins-*` targets,
and only when the task is about plugins.

---

## 7. Repository constraints

### Security (non-negotiable)

- Secure by default. Minimize the trusted computing base when adding code paths or deps.
- No ad-hoc crypto. Use vetted libraries and narrow interfaces; never invent or
  informally modify a scheme. Keep key establishment, key wrapping and payload
  encryption separated.
- Prefer constant-time / side-channel-aware primitives from maintained crates.
- Never log secrets, keys, tokens, plaintext sensitive material or raw credential
  artifacts. Zeroize sensitive material where practical; avoid unnecessary copies.
- No hidden behavior, implicit fallbacks, silent recovery or silent downgrade on
  security-critical paths. Failure modes must be explicit, deterministic, observable.
- Avoid `unsafe`; if unavoidable, justify it in a comment.
- High-risk areas: authn, authz, key management, storage barriers, TLS, PKI, secret handling.
- The build must stay free of `openssl-sys` and `aws-lc-sys` where the manifests say so —
  read the dependency comments in `Cargo.toml` before adding a crypto dep.

Review priority order: secret leakage → authn/authz correctness → crypto
correctness and misuse resistance → compatibility/migration safety →
operational debuggability → performance.

### HTTP API versioning

- **All new routes go under `v2/`.** `v1/` is frozen for Vault compatibility and
  takes bug fixes and security patches only — no new paths, no new operations.
- Mirror an extended subsystem under `v2/` and implement there. `v1` may delegate
  to `v2`, never the reverse.
- Tauri commands, logical-backend paths and tests for new functionality use `v2/`.
  Update `docs/api.md` and the relevant `features/*.md`.
- Breaking `v2` shape changes are allowed only before the first stable release that ships them.

### Change discipline

- Small, scoped, reviewable changes. No speculative rewrites, no unrelated
  refactors bundled into a security or correctness fix, no dependency churn.
- Preserve backwards compatibility and existing interfaces unless the break is
  intended and documented.
- Persisted formats: versioned, read-old/write-new migrations. Assume upgrades
  happen on live systems with old data. Prefer feature flags and staged rollouts.
- Code organization: small modules with clear ownership. When a subsystem outgrows
  a file or becomes reusable, split it before adding behavior — extract into
  `crates/` with a narrow public API and minimal dep surface (see the tiering in §2).
- Dependencies: maintained, widely reviewed, Rust-native where it removes external
  runtime deps. Document in the manifest *why* a new dep is needed. Run
  `make deps-unused` if you touch dependency lists.
- Code quality: descriptive names, explicit control flow, code that is readable under
  incident conditions. No broad catch-all error handling — bubble up errors with enough
  context for an operator. Comments only where they clarify non-obvious security or
  operational intent. Do not suppress a warning without a concrete stated reason.

### Per-crate versioning

**Two version schemes, and conflating them is the mistake.**

| | what | who moves it |
|---|---|---|
| **Product** | one number — `bvault --version`, the installer filenames. Root crate, `bvault-cli`, GUI. Not published. | `make bump-patch` / `-minor` / `-major` |
| **Library** | 38 independent numbers, one per publishable crate in `crates/`. Moved by *content*, not by release. | `make crates-bump` |

A release that ships the GUI must not republish `bv-shamir`, which has not
changed since it was extracted. So the release loop is:

```bash
make crates-plan               # what changed since its last published version
make crates-bump               # patch-bump exactly those (MINOR=<crate> if breaking)
make crates-publish-changed    # build + upload exactly those, in dependency order
make crates-tag-push           # publish the release record
```

`make crates-plan` derives everything from `cargo metadata` plus the
`<crate>-v<version>` git tags — publishable set, publish order, and what
changed. Do not maintain a list of crates anywhere; the last one drifted and
silently dropped `bv-core` and `bv-kernel` from every release.

**Three rules that keep a one-crate change a one-crate release.** All three
protect the same property, and breaking any of them makes every release a
whole-workspace release:

1. **Declare internal deps as a plain `version = "<x.y.z>"`, never `=<x.y.z>`.**
   A plain requirement is a caret one, matching every later patch in the same
   minor, so bumping `bv-errors` from 0.41.0 to 0.41.1 leaves its 32
   dependents' manifests untouched — their tarballs do not change, they are
   not republished, and a consumer resolves 0.41.1 by itself. An `=` pin
   turns every patch release into a whole-workspace release.
2. **Do not move dependencies into `[workspace.dependencies]`.** Cargo inlines
   the concrete version when it packages, so a workspace-level bump changes
   every crate's *published* manifest while changing no file in any crate
   directory — invisible to change detection, and a republish of all 38 when
   it is noticed. Declare deps per crate. (This is why the Phase 6 item to
   consolidate them was dropped; see the roadmap.)
3. **Every crate carries an explicit `publish` key** — `["uox-bastionvault"]`
   or `false`. No key means "any registry", i.e. crates.io. `make crates-plan`
   warns about a manifest missing one.

`make crates-bump` cannot tell whether your change is breaking — that is a
judgement about the crate's public API. Patch is the default; pass
`MINOR=<crate>` when you removed or changed a public item, and it will rewrite
dependents' requirements and tell you which ones now need republishing too.

**The library numbers were flat-synced once, on 2026-08-17, and that is not
the scheme resuming.** Every crate was created at `0.1.0` during the
decomposition and never moved, because the scheme above moves a crate only
when its content changes. Correct in principle and misleading in practice: a
manifest reading `0.1.0` says "brand new, never released" about the PKI engine
and the storage barriers, which is what ships in production. All 40 were set
to `0.41.0` — the number `bvault --version` prints — along with the 170
internal dependency requirements that had to move with them.

Two things follow, and neither is an invitation to do it again:

- **Do not re-sync.** The flat state costs the property the three rules
  protect: with every crate on one number there is no per-crate drift for
  `crates-plan` to detect. It cost nothing on the day, because nothing had
  been published; it costs a whole-workspace release every time it is
  repeated. Divergence is the correct end state — after the first release,
  `bv-shamir` staying at `0.41.0` while `bv-engine-pki` reaches `0.41.4` is
  the scheme working, not drift to be tidied up.
- **`make bump-*` still must not touch `crates/bv-*`.** The product version
  and the library versions are equal right now, which makes the two schemes
  look like one. They are not, and the moment a single crate is republished
  they stop matching.

### Testing requirements

- Add or update tests for every non-trivial behavior change; deterministic inputs
  and expected outputs.
- Crypto or storage changes: compatibility tests + malformed-input tests.
- Security fixes: regression coverage proving the old behavior cannot return.
- Do not call a migration complete without exercising old data, old config, or old API paths.

### GUI rules

- No `max-w-*` on a page container — pages fill the width inside the Layout sidebar.
  Use responsive grids (`grid-cols-1 sm:grid-cols-2 lg:grid-cols-3`).
- `min-w-0` + `truncate` on anything that can overflow (URLs, hostnames, long names).
- Max-width belongs only to `Modal` (`size="sm" | "md" | "lg"`).
- Forms: `grid grid-cols-2 gap-3`, `col-span-2` for full-width fields.

### Local Tauri MCP bridge

Approved for local GUI development only. Stays behind the GUI crate's
`mcp_local_dev` feature **and** `BASTION_TAURI_MCP=1`, bound to `127.0.0.1`
only. Never in release, production, CI packaging, or any build handling real
operator secrets. Entry point: `make run-dev-gui`. Treat its screenshots, DOM
snapshots, IPC events and logs as sensitive.

---

## 8. Tracking — required after every feature, phase or roadmap stage

1. `CHANGELOG.md` — entry under `[Unreleased]` in the right category (Added/Changed/
   Deprecated/Removed/Fixed/Security). Imperative mood, operator's perspective, grouped
   under a sub-heading, referencing the feature file or phase. See the HTML comment at
   the top of that file.
2. `roadmap.md` — feature status (Todo → In Progress → Done); move finished initiatives
   to Completed.
3. `features/<feature>.md` — update "Current State" and the phase table.
4. `roadmaps/<roadmap>.md` — mark phases Complete; keep "What Is Not Yet Implemented" honest.

Create a feature file for any significant new capability *before* implementing it.

---

## 9. Expected output from agents

State assumptions. Call out security-sensitive trade-offs. Identify migration risks
before changing persisted formats. Verify with tests rather than asserting. Report
what you actually ran and what failed. Leave the codebase more explicit and more
defensible than you found it.
