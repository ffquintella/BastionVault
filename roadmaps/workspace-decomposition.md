# Roadmap: Workspace Decomposition

Status: **Phase 0 done. Phase 1 started — the actix wart is cleared; the `bv-errors` extraction is blocked on a design call (see "`bv-errors` is not the cheap leaf this plan assumed").**

## Goal

Split the `bastion_vault` monolith into independently versioned,
independently buildable crates, so that **the cost of a small change is
proportional to the size of the change** rather than to the size of the
repository.

Three concrete outcomes, in order of value:

1. **CI runs the integration suite again.** Today `.github/workflows/tests.yml`
   deliberately skips `tests/` (~30 binaries), the hiqlite suites, and
   cucumber — because each `tests/` binary links the full dependency graph
   plus a 245 MB rlib. That is a coverage gap, not just a speed problem.
2. **A one-engine change compiles and tests one engine.** Editing the PKI
   engine should not recompile the SSH broker, the Tauri host, or the
   actix surface.
3. **Per-crate semver.** The plugin SDK, the client crate, and the
   engines can move at their own pace instead of being dragged to
   `0.39.x` by `make bump-patch`.

## Measured baseline

First-pass figures, measured by hand at `7d886f1` (warm `target/`, macOS host)
while scoping this roadmap. They are kept because the *ratios* are what motivated
the plan.

> **For comparing phases, use the Phase 0 table below and
> [docs/build-timings/baseline.md](../docs/build-timings/baseline.md), not this
> one.** These were single samples taken before `make bench-build` existed, and
> the measured noise floor is ~25% — so e.g. the 8.9s / 35.7s here and the
> 6.97s / 22.70s medians in Phase 0 describe the same tree, not a change. `lock`
> also reads 1202 here vs 1195 after the FerroGate SDK bump and the Phase 0
> dependency triage.

| Metric | Value |
|---|---|
| Cargo lock packages | 1202 |
| Rust source in `src/` | 173,084 lines across 451 files, **one crate** |
| `libbastion_vault.rlib` (debug) | **245 MB** |
| `target/` | 234 GB |
| `cargo check --lib`, no-op | 1.3 s |
| `cargo check --lib`, one leaf file touched | 8.9 s |
| `cargo nextest run --lib --no-run`, one leaf file touched | **35.7 s** |
| `tests/` binaries | 30, each a full link of the 245 MB rlib |
| `tests/` binaries that are PKI | **19 of 30** |
| CI timeout for the unit job | 90 minutes |

The incremental `cargo check` path is already well tuned (`profile.dev`
overrides, `-Z threads`, `make prune`). The remaining cost is **codegen
and linking**, which no profile tweak fixes — only a smaller compile unit
does.

### Churn, to aim the effort

Commits touching each area, last 300 commits (`gui/*` figures are
inflated by `make bump-*`, which rewrites `gui/src-tauri/Cargo.toml` on
every release — 214 of the 300):

| Area | Commits | Lines | Files |
|---|---|---|---|
| `src/cli` | 111 | 10,892 | 70 |
| `src/http` | 98 | 7,797 | 8 |
| `src/modules/credential` | 97 | 22,139 | 58 |
| `src/modules/pki` | 96 | 15,127 | 39 |
| `src/modules/system` | 90 | 8,648 | 5 |
| `src/storage` | 71 | 9,999 | 24 |
| `src/modules/policy` | 71 | 8,886 | 4 |
| `src/core.rs` | 69 | 1,699 | 1 |
| `src/logical` | 60 | 3,228 | 11 |
| `src/modules/rustion` | 44 | 11,490 | 19 |
| `src/plugins` | 20 | 7,437 | 16 |
| `src/modules/transit` | 0 | 3,155 | 19 |

## The one thing that blocks everything

`Core` and `modules` are **mutually dependent**:

- [`src/core.rs`](../src/core.rs) imports `modules::auth::AuthModule` and
  `modules::policy::PolicyModule`.
- [`src/module_manager.rs`](../src/module_manager.rs) constructs all 17
  default modules by name.
- Every module holds an `Arc<Core>`.

No module can become a crate until that cycle is cut. Everything else in
this roadmap is mechanical file movement.

The encouraging part is how *thin* the cycle actually is:

- **Only 80 of 228 module files reference `Core` at all.** The substance
  of the engines is already `Core`-free: PKI 2/39 files, Transit 1/19,
  TOTP 2/10, `cert_lifecycle` 2/8, LDAP 2/9.
- The `Core` surface modules consume is ~35 members, and seven of them
  account for most uses: `handle_request` (89), `module_manager` (43),
  `state` (40), `barrier` (40), `router` (23), `get_system_view` (21),
  `add_logical_backend` / `delete_logical_backend` (33).
- The 43 `module_manager.get_module::<T>()` cross-module lookups resolve
  to **exactly five** targets — `AuthModule`, `IdentityModule`,
  `PolicyModule`, `NamespaceModule`, `ResourceGroupModule` — plus a
  handful of self-lookups (`AppRoleModule` fetching `AppRoleModule`) that
  are just an awkward way to reach `&self` and delete outright.

So the graph is a **kernel of five tenancy/identity services** that
everything else consumes through five narrow traits, and a **tier of leaf
engines** that need nothing else.

### Cross-layer warts to fix first

Each is a handful of lines and each blocks a Tier-0 extraction:

| Wart | Sites | Fix |
|---|---|---|
| ~~`errors.rs` imports `actix_web::http::StatusCode`~~ | 2 | **Done.** `response_status()` returns `u16`; the actix `ResponseError` impl in `src/http/mod.rs` maps it. The header-decode variant no longer wraps an actix type. |
| `src/audit` → `crate::modules` | 2 (`sys_emit.rs`, `entry.rs`) | Take the token store via trait; move `NS_PATH_META` to the shared contract crate |
| `src/mount.rs` → `crate::plugins` | 2 | Invert: the plugin runtime registers its backend factory with the mount table |
| `src/metrics` → `crate::plugins` | 1 | Invert: plugins register their collectors |
| `src/storage` → `crate::http` | 1 | Doc comment only — no real coupling |

Verified clean leaves, needing no inversion at all: `src/logical`,
`src/utils`, `src/shamir.rs` reference **only** `crate::errors`;
`src/cache` references only `crate::storage`.

Note on the actix wart, since the original advice here was wrong: "use
`http::StatusCode`, it's already a direct dep" would **not** have worked.
actix-web 4 is built on `http 0.2` while this workspace also carries a direct
`http 1` dep — both majors are in the graph — so `http::StatusCode` is a
*different type* from the one `actix_web::http::StatusCode` aliases. Returning a
plain `u16` from `response_status()` sidesteps the mismatch and is what landed.

### `bv-errors` is not the cheap leaf this plan assumed

Discovered while doing the extraction: `RvError` carries `#[from]` conversions for
**19 external crates** — `bcrypt`, `chrono`, `diesel`, `hcl`, `hex`, `http`,
`humantime`, `ipnetwork`, `lockfile`, `pem`, `r2d2`, `regex`, `rustls`,
`serde_json`, `serde_yaml`, `tokio`, `ureq`, `url` (plus `std::io`).

Since *every* crate in the target graph depends on the error type, a naive
`bv-errors` would put `rustls`, `ureq`, `diesel`, and `tokio` at the bottom of the
dependency graph and hand them to every leaf engine. That still buys a separate
compilation unit for a file that rarely changes, but it does **not** shrink what
a leaf crate has to build — which was half the point.

So `bv-errors` needs its conversions **feature-gated**: `default-features = false`
gives `std` + `thiserror` only, and each consumer opts into the `From` impls it
actually needs (`features = ["rustls", "ureq"]`). Concretely that means a
`#[cfg(feature = ...)]` on each of the 19 variants, and on the corresponding arms
in `response_status()` and the hand-written `PartialEq`.

That is a design decision with a real cost, and it should be made deliberately
rather than discovered halfway through a mechanical file move — which is why the
extraction stopped here. Alternatives worth weighing before committing to it:

1. **Feature-gate all 19** (above). Most faithful to the goal; most churn, and
   every consumer's `Cargo.toml` grows a feature list.
2. **Drop the `#[from]` conversions** and make call sites map explicitly, as the
   actix header variant now does. Smallest resulting graph and no features at
   all, but it touches every `?` that relies on an implicit conversion — a much
   wider diff than Phase 1 wants.
3. **Accept the fat leaf for now.** Ship `bv-errors` with all 19 deps, take the
   compile-unit win, and revisit once the engine crates exist and the cost is
   measurable with `make bench-build` rather than argued.

Option 3 is the cheapest way to keep Phase 1 moving and defers the decision to a
point where it can be measured; option 1 is where it likely ends up.

## Target crate graph

```
Tier 0 — substrate (no cycles; extract as-is)
  bv-errors      RvError (149 variants), no actix
  bv-utils       src/utils                          4,839
  bv-shamir      src/shamir.rs                        685
  bv-logical     src/logical — Request/Response/
                 Backend/LogicalBackend/Path/Field   3,228
  bv-storage     src/storage + src/cache; hiqlite
                 and mysql behind features           9,999
  bv-audit       src/audit                           1,549
  bv-metrics     src/metrics                           945

Tier 1 — kernel contract (the cycle-breaker)
  bv-kernel-api  VaultCtx, TokenStore, IdentityStore,
                 PolicyStore, NamespaceRegistry,
                 ResourceGroupStore, ModuleRegistry

Tier 2 — kernel implementation
  bv-core        core.rs, router.rs, mount.rs, handler.rs,
                 module_manager.rs, seal, dos, hsm
  bv-kernel      auth + identity + policy + namespace +
                 resource_group (one crate: they are
                 mutually entangled)                43,000

Tier 3 — engines and auth backends (each: Tier 0 + bv-kernel-api only)
  bv-engine-pki                 15,127   96 commits   19 test binaries
  bv-engine-rustion             11,490   44 commits
  bv-engine-files                4,948
  bv-engine-resource             3,429
  bv-engine-transit              3,155    0 commits
  bv-engine-ssh                  2,935
  bv-engine-ldap                 2,728
  bv-engine-notifications        1,955
  bv-engine-totp                 1,635
  bv-engine-cert-lifecycle       1,542
  bv-engine-ssh-broker           1,233
  bv-engine-kv                   1,323   (kv + kv_v2)
  bv-auth-{approle,userpass,fido2,oidc,saml,ferrogate,cert}
                                22,139   97 commits  (split from credential/)

Tier 4 — assembly
  bv-server      src/http                            7,797
  bvault-cli     src/cli                            10,892  111 commits
  bastion_vault  facade: re-exports + registration
  gui/src-tauri  depends on the facade
```

Existing crates keep their place: `bv_crypto` and `bv_plugin_surface` are
Tier 0, `bv-plugin-manifest` / `bastion-plugin-sdk` /
`bastion-plugin-testkit` / `bv-plugin-pack` are already independent, and
`bv-client` already documents "zero dependencies on the bastion_vault
server crate" — it is the model the engine crates should follow.

## Phases

Every phase is independently mergeable and behaviour-preserving. The
gate for each is: `make test-all` green, `make plugins-test` green,
`cargo check --workspace` green, and no change to the public
`bastion_vault::` paths the GUI consumes — the Tauri host is the
compatibility canary.

### Phase 0 — Instrument, before changing anything — **done**

- **`make bench-build`** ([scripts/bench-build.sh](../scripts/bench-build.sh))
  measures four scenarios — `check-noop`, `check-leaf`, `check-core`,
  `test-build-leaf` — as the **median of 3 samples**, and appends a row to
  [docs/build-timings/baseline.md](../docs/build-timings/baseline.md).
  Median, not one sample, because the measured spread is ±13–16% per scenario;
  **a phase must move a number by more than ~25% to be believed.**
- **`make build-timings`** writes the `--timings` HTML; the pre-decomposition
  artefact is archived at `docs/build-timings/lib-selftime-d04a72c.html`. It
  shows the monolith compiling as **one unit in 25.94s** with all deps cached —
  the number the split divides.
- **`make deps-unused`** ([scripts/deps-unused.sh](../scripts/deps-unused.sh))
  wraps `cargo-machete`, scoped to the crates we own (the raw sweep also walks
  `IronRDP/`, `third_party/`, and `plugins-ext/`, which we don't). Wired into
  [tests.yml](../.github/workflows/tests.yml) as an **advisory** job that cannot
  block a merge.

**Baseline** (`d04a72c`, 10 cores, warm target, medians):

| scenario | value |
|---|---|
| `check-noop` | 0.48s |
| `check-leaf` | 6.97s |
| `check-core` | 7.65s |
| `test-build-leaf` | 22.70s |
| lib rlib (debug) | 245 MB |
| lock packages | 1195 |

#### Findings

**`check-leaf` and `check-core` are the same number.** 6.97s vs 7.65s, with
sample ranges that overlap almost entirely. Both files are in the same crate, so
touching either invalidates the same compilation unit — the build system cannot
tell a self-contained 3,155-line engine apart from the 1,699-line object every
module depends on. Both columns stay in the table specifically to be watched
**diverging** as Phases 2 and 3 land.

**Dependency triage: 5 dead edges removed, 8 false positives documented.**
Dropped `foreign-types`, `glob`, `serde_derive` (root), `serde`
(`bv-plugin-pack`), `futures-util` and `ironrdp-pdu` (GUI — the umbrella
`ironrdp` crate already enables the `pdu` feature). **`lock` did not move:
1195 before and after** — every one of those crates is still in the graph
transitively, so this bought a clean signal and no compile time. No speedup
should be attributed to Phase 0.

The remaining `cargo machete` hits are all blind spots of a static `use` scan,
now carried in `[package.metadata.cargo-machete] ignored` lists *with reasons*:
package name ≠ lib name (`hcl-rs`→`hcl`, `smolder-smb-core`→`smolder_core`),
attribute-only use (`serde_bytes` via `#[serde(with = ...)]`), and — the category
worth care — **dependencies declared to pin a feature rather than to be
imported**: `tower`'s `util`, `rusb`'s `vendored`, `webpki-roots`'s defaults,
`rustls-pki-types`'s major, and `bv-client`'s `rustls/aws_lc_rs`. Deleting one of
those changes feature unification across the graph, not just a manifest line.

**`cargo-hakari` deferred to the end of Phase 1, on evidence.** The problem it
solves is not measurable here yet. Alternating `cargo check --workspace` with
`cargo check -p <crate>` does **not** oscillate: after the first build of a given
configuration (a one-time 15.94s for `-p bv_crypto`), every subsequent switch is
a no-op (0.26–0.72s). With 12 members there is no churn to remove. Against that,
adding it now has a concrete cost: hakari injects a `workspace-hack` dependency
into every member, which collides with the `publish = ["uox-bastionvault"]` setup
described under Phase 6 — a published crate would carry a dependency on a
local-only crate, forcing `scripts/publish-crates.sh` onto `cargo hakari publish`.
Revisit when the member count climbs in Phase 1 and re-run the oscillation test;
adopt only if it oscillates.

**Exit:** met — a reproducible number to beat, an archived timings artefact, and
a CI job that reports dependency drift.

### Phase 1 — Tier 0 substrate

Extract, in this order, each as its own PR:

1. `bv-errors` (fix the actix import first)
2. `bv-utils`, `bv-shamir`
3. `bv-logical`
4. `bv-storage` (+ `bv-cache` folded in) — this is the phase that moves
   `hiqlite`, `diesel`, and `rusty-s3` out of the monolith's compile unit
5. `bv-audit`, `bv-metrics` (after their two inversions)

Re-export every moved path from `src/lib.rs` (`pub use bv_logical as logical;`)
so no call site outside the moved directory changes in this phase.

**Expected:** the substrate stops recompiling on engine edits. Touching
an engine no longer invalidates ~19k lines of storage/logical code.
Modest wall-clock win; the real value is that Phases 2–4 become possible.

### Phase 2 — Break the `Core` ↔ `modules` cycle

The crux. No files move; only the direction of dependency changes.

1. Define `bv-kernel-api` with the traits the measurements above
   identified:
   - `VaultCtx` — `barrier()`, `system_view()`, `state()`, `router()`,
     `handle_request()`, `add_logical_backend()`,
     `delete_logical_backend()`, `add_handler()`
   - `TokenStore`, `IdentityStore`, `PolicyStore`, `NamespaceRegistry`,
     `ResourceGroupStore` — one per `get_module::<T>()` target
   - `ModuleRegistry` — replaces `ModuleManager::get_module`'s
     `Arc::downcast` with typed accessors
2. Delete the ~12 self-lookups (`get_module::<AppRoleModule>("approle")`
   inside `AppRoleModule`) by threading `&self`.
3. Change engine signatures from `Arc<Core>` to `Arc<dyn VaultCtx>`,
   module by module, cheapest first: transit (1 file), totp (2),
   `cert_lifecycle` (2), ldap (2), pki (2), files (3).
4. Invert registration: `ModuleManager::set_default_modules` stops naming
   17 concrete types and instead consumes a `Vec<Box<dyn ModuleFactory>>`
   that `src/lib.rs` — the assembly point — supplies.

`impl VaultCtx for Core` keeps runtime behaviour byte-identical. This
phase should land with **zero** change in test outcomes; if any test
changes, the abstraction is wrong.

**Risk:** this is the one phase with real design content. Budget for it
being revised once. Keep it behind no feature flag — a half-inverted
graph is worse than either end state.

### Phase 3 — Engines out, starting with PKI

Order by (churn × size) ÷ coupling. PKI first, and not narrowly:

- 15,127 lines, 96 of the last 300 commits
- **19 of the 30 `tests/` binaries** are PKI (`test_pki_*.rs`,
  `test_cert_lifecycle_*.rs`, `test_rustion_master_pki_issue.rs`)
- only 2 of its 39 files touch `Core`

Move `tests/test_pki_*.rs` into `crates/bv-engine-pki/tests/`. Those 19
binaries then link the PKI crate plus substrate instead of the 245 MB
monolith rlib — which is what makes them cheap enough for CI to run at
all. **This single extraction closes most of the current integration-test
coverage gap.**

Then, in descending order: `rustion`, `files`, `transit`, `ssh` +
`ssh_broker`, `totp`, `ldap`, `notifications`, `cert_lifecycle`, `kv` +
`kv_v2`, `resource` + `resource_group`.

Finally split `credential/` (22,139 lines, 58 files, the single largest
directory and highest-churn area) into one crate per backend. Do it last:
it is the most `Core`-entangled tier-3 code (12 of 58 files) and benefits
most from Phase 2 having settled.

**Expected:** a PKI-only change compiles PKI plus the facade, not 173k
lines. Target: the 35.7 s test-binary rebuild drops to single digits for
a leaf-engine edit.

### Phase 4 — Assembly split

- `bv-server` — `src/http`, taking actix out of every engine's tree
- `bvault-cli` — `src/cli` (111 commits; deserves to build alone)
- `bastion_vault` becomes a thin facade: re-exports plus the registration
  list that wires engines into a `ModuleRegistry`
- `gui/src-tauri` keeps depending on the facade at first; once the engine
  crates are stable, narrow it to `bv-core` plus the engines the embedded
  vault actually mounts. **This is the biggest single GUI-CI win** —
  today `gui/src-tauri/Cargo.toml` carries
  `bastion_vault = { path = "../.." }`, so every server-side change
  rebuilds the Tauri host.

### Phase 5 — CI shape

Only meaningful after Phase 3; the workflow changes are cheap once the
crates exist.

- Path-filtered jobs (`dorny/paths-filter`) → matrix of
  `cargo nextest run -p <crate>` for affected crates only.
- **Re-enable `tests/`**, per crate, now that each links a small crate
  rather than the monolith. Same for the hiqlite suites, which stay on
  `cargo test` for their process-global port allocator (see
  `.config/nextest.toml`) but now only rebuild when `bv-storage` changes.
- Per-crate `Swatinem/rust-cache` keys, plus `sccache` with a shared
  bucket for the invariant substrate.
- Keep one `cargo check --workspace` gate job so a green matrix can never
  hide a broken assembly.
- Update `.config/nextest.toml` and the `NOTE ON SCOPE` comment block in
  `tests.yml` as exclusions are retired — that comment is currently the
  honest record of what CI does not cover, and it must stay honest.

### Phase 6 — Independent versioning and publishing

**The registry plumbing is already in place** (branch
`feat/workspace-decomposition`), so every crate the earlier phases create
has somewhere to go from day one:

- `.cargo/config.toml` declares the `uox-bastionvault` Cloudsmith registry
  (sparse index).
- The seven existing library crates carry `publish = ["uox-bastionvault"]`,
  a `repository`, and `version` + `registry` on their internal deps.
- `scripts/publish-crates.sh` (+ `make crates-publish{,-dry}`,
  `make crates-verify`, `make crates-login`) publishes in topological
  order, dry-run by default, refusing a dirty tree.
- Credential hygiene is documented and gitignored — see
  [docs/publishing-crates.md](../docs/publishing-crates.md).

Each new crate from Phases 1 and 3 must therefore land with: `version`,
`license`, `description`, `repository`, `publish = ["uox-bastionvault"]`,
`version` + `registry` on every internal dep, and an entry in the
script's ordered `CRATES` list.

Remaining Phase 6 work:

- Move shared dependency versions to `[workspace.dependencies]`.
- Resolve the root crate's unpublishability — it path-depends on the
  vendored, unpublished `ferro-*` crates in
  `third_party/ferrogate-sdk-rust/`. Either publish those to the same
  registry or keep the facade local. See
  [docs/publishing-crates.md](../docs/publishing-crates.md)
  § Known constraints.
- Wire tag-triggered publishing into CI.
- Adopt `release-plz` or `cargo-release` for per-crate semver from
  conventional commits.
- Rework `make bump-*`: today `_bump-write` rewrites `Cargo.toml`,
  `gui/src-tauri/Cargo.toml`, `gui/package.json`, and `tauri.conf.json`
  in lockstep. Keep that lockstep for the **shipped product version**
  (server, CLI, GUI, installers — the thing operators see), and let the
  library crates version independently underneath it.
- `CHANGELOG.md` stays the product changelog. Per-crate changelogs only
  for crates that are actually published.

## Ordering rationale

Phase 1 is safe and unlocks Phase 2. Phase 2 has the design risk and
zero visible payoff — resist reordering it after Phase 3, because
extracting an engine while the cycle exists means re-doing it. Phase 3 is
where the numbers move. Phases 5 and 6 are policy, not engineering, and
can slip without blocking anything.

If only one phase is ever done, do **Phase 2 plus the PKI half of
Phase 3**: it cuts the cycle, proves the pattern on the highest-churn
engine, and hands CI back 19 integration-test binaries it currently
cannot afford to run.

## Non-goals

- No behaviour change, no API change, no dependency upgrades ride along.
- Not splitting the repository. One workspace, many crates; the
  `plugins-ext` submodule pattern stays the exception.
- Not touching the plugin ABI. `bv_plugin_surface` and
  `bastion-plugin-sdk` already define a stable module boundary and are
  the proof this decomposition is achievable.

## Tracking

Update on each phase completion:

- `CHANGELOG.md` under `[Unreleased]` → **Changed**
- `roadmap.md` — one row, `Workspace Decomposition`, Todo → In Progress → Done
- this file — phase status and the measured delta against the baseline table
