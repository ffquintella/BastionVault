# Roadmap: Workspace Decomposition

Status: **every phase is done — 0, 1, 2, 3, 4, 4.5, 5 and 6.** What is left is
one operational step this roadmap cannot do for itself: cutting the first
actual release to the registry, by hand, because it creates 38 crate versions
that can never be reused.

Phase 5 delivered outcome #1 below: **CI runs the integration suite again**, plus
the hiqlite and cucumber suites, plus a per-crate isolation check — and it runs
only what a change can reach, derived from `cargo metadata` rather than from a
hand-maintained list of path globs.

The Tier 2 split this document kept predicting and never scheduling has
landed: `bv-core` (6,424 lines) and `bv-kernel` (32,017) came out of the root
crate in Phase 4.5, which is written up below. `bastion_vault` is finally what
the target graph called it — a facade — at 27,921 lines, **12,095 of which are
test modules that could not travel**. The production facade is under 16k.

Phase 1 shipped eight Tier 0/1 crates — `bv-errors`, `bv-shamir`,
`bv-context`, `bv-metrics`, `bv-storage`, `bv-logical`, `bv-utils`,
`bv-audit` — in an order the original plan got wrong three separate times.
See "Phase 1" below for what landed, what it cost, and the measurement bug
that caused the misordering.

Phase 2 is complete on both halves: the `Core` ↔ `modules` cycle is cut *and*
the sibling cycle is cut. Measured at the end of that phase:

| measured on production code (`#[cfg(test)]` excluded) | phase start | after 2a | **after 2b** |
|---|---|---|---|
| `Core` references in the 14 Tier 3 engine directories | 86 files | 0 | **0** |
| `get_module::<T>()` in Tier 3 + `src/audit` + `src/plugins` | ~40 | ~40 | **0** |
| Tier 3 references to *any other* module directory | 12 | 12 | **0** |
| Engine entry points named by `Core::post_unseal` | 6 | 6 | **0** |
| Modules named by `Core::flush_caches` | 2 | 2 | **0** |
| `src/audit` → `crate::modules` | 2 | 1 | **0** |
| `VaultCtx::module_manager()` | — | present | **removed** |

`get_module::<T>()` survives in 79 production sites, all inside the kernel tier
(`auth`, `identity`, `policy`, `namespace`, `resource_group`, `system`), plus 10
in the assembly layer (`core.rs`, `src/http`). Both are by design — see
"Tiering" below. The 12 remaining Tier 3 sites are all `#[cfg(test)]`, and all
of them also use `crate::test_utils`, so they cannot travel into an engine
crate regardless; they become `tests/` binaries in Phase 3.

> **Read the "re-measured" blocks below before planning against this
> document.** Several of its load-bearing figures were derived from greps that
> could not see brace-grouped `use crate::{...}` imports or that counted doc
> comments, and they were wrong in ways that changed the plan: the "clean
> leaves" are not leaves, Phase 2 had ~101 cross-module call sites rather than
> 43, and three of the five Tier 3 ↔ Tier 3 "cycles" were prose.
>
> **This document has now measured its own dependency graph wrong three
> times, each time with a different broken regex, and each time the error
> changed the extraction order.** If you need the graph again, do not write a
> fourth grep — match braces by counting, expand one level of nesting, and
> split `#[cfg(test)]` blocks out before counting. The third failure is
> written up under "Phase 1 § the third measurement error"; it is the one that
> is easiest to repeat, because the regex looked correct.

## Goal

Split the `bastion_vault` monolith into independently versioned,
independently buildable crates, so that **the cost of a small change is
proportional to the size of the change** rather than to the size of the
repository.

Three concrete outcomes, in order of value:

1. **CI runs the integration suite again.** `.github/workflows/tests.yml` used
   to skip `tests/` (~30 binaries), the hiqlite suites, and cucumber — because
   each `tests/` binary links the full dependency graph plus a 245 MB rlib. That
   was a coverage gap, not just a speed problem. **Met in Phase 5.**
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
- The `module_manager.get_module::<T>()` cross-module lookups resolve
  to **exactly five** targets — `AuthModule`, `IdentityModule`,
  `PolicyModule`, `NamespaceModule`, `ResourceGroupModule` — plus
  self-lookups (`AppRoleModule` fetching `AppRoleModule`).

  **Re-measured, with two corrections to the figures above.** The set of
  five targets is confirmed. The *count* is not: "43" matches the call
  sites written literally as `core.module_manager.get_module` (42 today),
  but the rest arrive through `self.core.module_manager.` (9) or a local
  binding. Production call sites in `src/modules`, excluding
  `#[cfg(test)]`:

  | target | prod sites |
  |---|---|
  | `IdentityModule` | 37 |
  | `AuthModule` | 25 |
  | `NamespaceModule` | 16 |
  | `PolicyModule` | 14 |
  | `ResourceGroupModule` | 9 |
  | **kernel-five total** | **101** |

  So Phase 2 has ~101 production call sites to route through traits, not
  43 — a 2.4× sizing miss. A further 17 live in test modules.

  The self-lookups are **11 production sites** (`RustionModule` ×9,
  `NotificationsModule` ×1, `SshBrokerModule` ×1), which matches the
  original "~12" estimate. But "just an awkward way to reach `&self` and
  delete outright" is wrong for 9 of the 11: they sit inside **detached
  `tokio::task::spawn` loops** (`rustion/poller.rs`, `telemetry.rs`,
  `attest_timer.rs`, `probe.rs`), started from `Core::post_unseal`
  (`src/core.rs:1025`) with an `Arc<Core>`. They re-resolve the module on
  every tick *deliberately* — modules are registered after `Core` is
  built, and a sealed vault has none — so there is no `&self` to thread.
  The fix is to capture a `Weak<RustionModule>` at registration and
  `upgrade()` per tick, which preserves the late binding without a
  name-keyed `Arc::downcast`. The remaining 2 (`NotificationsModule`,
  `SshBrokerModule`) are held by a struct that already owns a `core`
  field and can hold the service handle instead.

  All 7 `AppRoleModule` lookups are test-only, so they are test-fixture
  cleanup rather than production coupling.

So the graph is a **kernel of five tenancy/identity services** that
everything else consumes through five narrow traits, and a **tier of leaf
engines** that need nothing else.

### Cross-layer warts to fix first

Each is a handful of lines and each blocks a Tier-0 extraction:

| Wart | Sites | Fix |
|---|---|---|
| ~~`errors.rs` imports `actix_web::http::StatusCode`~~ | 2 | **Done.** `response_status()` returns `u16`; the actix `ResponseError` impl in `src/http/mod.rs` maps it. The header-decode variant no longer wraps an actix type. |
| ~~`src/audit` → `crate::modules`~~ | 2 (`sys_emit.rs`, `entry.rs`) | **Done** (Phase 2). `sys_emit.rs` takes the token store through `kernel_api::auth::TokenService`; `NS_PATH_META` and its two siblings moved to `kernel_api::namespace`, re-exported from `token_binding`. |
| `src/mount.rs` → `crate::plugins` | 2 | Invert: the plugin runtime registers its backend factory with the mount table |
| ~~`src/metrics` → `crate::plugins`~~ | 1 | **Done** (Phase 1). `MetricsManager::register_collector` takes the registration function; the two assembly points that build a manager supply the plugin collector. |
| ~~`src/storage` → `crate::http`~~ | 1 | **Done** (Phase 1). Was a doc comment; rewritten as prose when `src/storage` became `bv-storage`. |

~~Verified clean leaves, needing no inversion at all: `src/logical`,
`src/utils`, `src/shamir.rs` reference **only** `crate::errors`;
`src/cache` references only `crate::storage`.~~

**That claim was wrong, and it was wrong in a way worth recording.** It came
from grepping `crate::[a-z_]+`, which cannot see a brace-grouped import: in
`use crate::{ errors::RvError, storage::Storage };` the character after
`crate::` is `{`, so the pattern matches nothing. Multi-line `use` blocks —
the dominant style in this repo — were therefore invisible to the survey, and
three of the four "clean leaves" are not leaves at all.

Re-measured with a scanner that normalises `use` statements, expands one level
of braces, and separates production code from `#[cfg(test)]` modules
(the distinction matters: a test that needs the root crate's `test_utils`
cannot travel into a new crate at all, because that would be a dependency
cycle, whereas a production edge merely sets the tier):

| module | production deps beyond `errors`/self | test-only deps |
|---|---|---|
| `src/shamir.rs` | **none** | none |
| `src/context.rs` | **none** | none |
| `src/metrics` | `plugins` | `test_utils` |
| `src/cache` | `metrics`, `modules`, `storage` | `storage` |
| `src/storage` | `cache`, `metrics`, `schema`, `http` (doc only) | `test_utils` ×6 |
| `src/logical` | `context`, `handler`, `storage` | `storage`, `test_utils` |
| `src/utils` | `logical`, `shamir`, `storage` | `logical`, `storage`, `test_utils` |
| `src/audit` | `core`, `logical`, `modules`, `storage` | `logical`, `test_utils` |

Consequences for the plan:

- **Only `shamir` and `context` are true Tier 0 leaves.** `context` was not
  even in the Tier 0 list; it belongs there, and `bv-logical` needs it.
- **`src/utils` is Tier 1, not Tier 0.** `salt.rs` needs `crate::storage`,
  `token_util.rs` needs `crate::logical`, `seal.rs` needs `crate::shamir`.
  It can only be extracted after those.
- **`src/cache` ↔ `src/storage` is mutual** (3 edges each way), which
  independently confirms folding them into one crate.
- **`bv-logical` and `bv-audit` are blocked on Phase 2, not on Phase 1.**
  `Request` holds `pub handler: Option<Arc<dyn Handler>>`, and `Handler`
  (`src/handler.rs`) takes `Arc<Core>` and `cli::config::Config`; `src/audit`
  reaches `crate::core::Core` directly. Neither can move until the
  `Core` ↔ `modules` cycle is cut. **The ordering rationale below therefore
  has it backwards for these two: Phase 2 unlocks them, not the reverse.**

Note on the actix wart, since the original advice here was wrong: "use
`http::StatusCode`, it's already a direct dep" would **not** have worked.
actix-web 4 is built on `http 0.2` while this workspace also carries a direct
`http 1` dep — both majors are in the graph — so `http::StatusCode` is a
*different type* from the one `actix_web::http::StatusCode` aliases. Returning a
plain `u16` from `response_status()` sidesteps the mismatch and is what landed.

### `bv-errors` is not the cheap leaf this plan assumed

Discovered while doing the extraction: `RvError` carries `#[from]` conversions for
**20 external crates** — `anyhow`, `bcrypt`, `chrono`, `diesel`, `hcl`, `hex`,
`http`, `humantime`, `ipnetwork`, `lockfile`, `pem`, `r2d2`, `regex`, `rustls`,
`serde_json`, `serde_yaml`, `tokio`, `ureq`, `url` (plus `std::io`). `anyhow`
hides in an inline `#[from]` rather than a `source:` field — worth knowing,
because the first grep for these missed it and the build caught it.

Since *every* crate in the target graph depends on the error type, a naive
`bv-errors` would put `rustls`, `ureq`, `diesel`, and `tokio` at the bottom of the
dependency graph and hand them to every leaf engine. That still buys a separate
compilation unit for a file that rarely changes, but it does **not** shrink what
a leaf crate has to build — which was half the point.

So `bv-errors` needs its conversions **feature-gated**: `default-features = false`
gives `std` + `thiserror` only, and each consumer opts into the `From` impls it
actually needs (`features = ["rustls", "ureq"]`). Concretely that means a
`#[cfg(feature = ...)]` on each of the 20 variants, and on the corresponding arms
in `response_status()` and the hand-written `PartialEq`.

That is a design decision with a real cost, and it should be made deliberately
rather than discovered halfway through a mechanical file move — which is why the
extraction stopped here. Alternatives worth weighing before committing to it:

1. **Feature-gate all 20** (above). Most faithful to the goal; most churn, and
   every consumer's `Cargo.toml` grows a feature list.
2. **Drop the `#[from]` conversions** and make call sites map explicitly, as the
   actix header variant now does. Smallest resulting graph and no features at
   all, but it touches every `?` that relies on an implicit conversion — a much
   wider diff than Phase 1 wants.
3. **Accept the fat leaf for now.** Ship `bv-errors` with all 20 deps, take the
   compile-unit win, and revisit once the engine crates exist and the cost is
   measurable with `make bench-build` rather than argued.

Option 3 is the cheapest way to keep Phase 1 moving and defers the decision to a
point where it can be measured; option 1 is where it likely ends up.

**Decided: option 3.** The dependency count is not what blocks the extraction
anyway — the orphan rule is.

### The real blocker: the orphan rule on `impl ResponseError for RvError`

Attempted, then reverted, so the cost is known rather than guessed. The move
itself is trivial (`git mv src/errors.rs crates/bv-errors/src/lib.rs`, a manifest,
`pub use bv_errors as errors;` plus a re-export of the three `#[macro_export]`
macros so all ~200 `crate::bv_error_*!` call sites stay untouched). It compiles
until this:

```
error[E0117]: only traits defined in the current crate can be implemented
              for types defined outside of the crate
   --> src/http/mod.rs:108:1
    |
108 | impl ResponseError for RvError {
```

Once `RvError` is foreign, so are both halves of that impl. Actix needs
`ResponseError` on whatever a route handler returns, so the fix is a newtype in
`src/http` — `struct HttpError(RvError)` with `ResponseError for HttpError` and
`From<RvError> for HttpError`. Measured blast radius:

| | count |
|---|---|
| handler signatures `Result<HttpResponse, RvError>` (105 of them in `sys.rs` alone) | **113** |
| `Err(...)` sites needing an explicit `.into()` — `return Err(e)` does **not** apply `From`, only `?` does | **59** |
| `RvError::` / `bv_error_*!` expressions in `src/http` to re-check | 64 |

Feature-gating `ResponseError` inside `bv-errors` is **not** a way out: cargo
unions features across the graph, so one consumer enabling `actix` gives every
leaf engine actix-web again.

So `bv-errors` is not a file move — it is a ~200-site mechanical refactor of the
HTTP error surface, and HTTP status codes on a secrets server are security-
relevant (they decide what a caller learns about why a request failed). It wants
its own PR with the full suite plus a pass over `src/http/sys.rs`'s status
assertions, not a tail-end change.

**Recommended order for the rest of Phase 1:** do the genuinely clean leaves
first, and come back to `bv-errors` with the `HttpError` newtype as its own
change. `src/logical`, `src/utils`, and `src/shamir.rs` reference *only*
`crate::errors` — so extracting them first means they depend on the root crate's
`errors` module unchanged, and each is a real file move with no orphan-rule
surprise. That reorders the phase but not its content.

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

### Phase 1 — Tier 0 substrate — **done**

Eight crates, in this order, each its own commit with the full suite as its
gate:

| # | crate | lines | what it actually took |
|---|---|---|---|
| 1 | `bv-errors` | 622 | the `HttpError` newtype in `src/http` (orphan rule); 149 signatures, 7 `.into()` |
| 2 | `bv-shamir` | 685 | true leaf |
| 3 | `bv-context` | 86 | true leaf; added to Tier 0, was not in the plan |
| 4 | `bv-metrics` | 618 | inverting `MetricsManager::new` → `plugins::metrics::register`; actix middleware left behind |
| 5 | `bv-storage` (+ `cache`, `schema`) | 11,067 | `TokenCache` made generic; storage test fixtures moved to a `test-support` feature |
| 6 | `bv-logical` (+ `handler`) | 3,341 | deleting the dead `Handler::post_config` hook |
| 7 | `bv-utils` | 4,841 | nothing — but it had to come last, being Tier 1 |
| 8 | `bv-audit` | 1,128 | `AuditBroker::new` off the kernel handle; `sys_emit` left above the crate |

**Measured outcome** (`606f4f8`, versus the Phase 0 baseline at `d04a72c`):

| | before | after |
|---|---|---|
| `src/` (the root compilation unit) | 173,938 lines | **154,373** |
| `libbastion_vault.rlib` (debug) | 245 MB | **230 MB** |
| workspace members | 12 | **20** |
| `cargo check` after editing a storage file | ~7.7s (it was `src/storage`, so `check-core`-class) | **0.78s** (`cargo check -p bv-storage`) |
| `check-leaf` / `check-core` | 6.97s / 7.65s | 9.26s / 8.82s — **unmoved, and still equal** |
| unit / integration / doctests | 1289 / 1358 / 17 | **1289 / 1358 / 17** |

Read the last two rows together. `check-leaf` and `check-core` both touch
files that are *still in the root crate*, so Phase 1 was never going to
separate them — Phase 3 is what does that, and the roadmap says so in the
Phase 0 findings. What Phase 1 bought is the row above them: work on the
storage substrate is now a 0.78s loop instead of a ~8s one, because it is a
crate you can check on its own. And eleven dependencies — `hiqlite`,
`diesel`, `r2d2`, `rusty-s3`, `keyring`, `sysinfo`, `libc`, `lockfile`,
`as-any`, `blake2b_simd`, `enum-map` — are no longer dependencies of
`bastion_vault` at all; they belong to the crates that use them. Phase 1
added no new external dependency.

**No wall-clock speedup should be attributed to Phase 1 on the four
benchmark scenarios.** They did not move, and the noise floor is ~25%.

#### The third measurement error

The plan below was rewritten twice on re-measurement, and then a *third*
time during the work, because the scanner used to re-measure it was also
wrong. It matched brace-grouped imports with `crate::\{([^}]*)\}` — which
stops at the **first** `}`, not the matching one. So in

```rust
use crate::{
    context::Context,
    errors::RvError,
    handler::{HandlePhase, Handler},   // <- the scan ends here
    logical::{auth::Auth, ...},
    storage::{Storage, StorageEntry},  // <- never seen
};
```

everything after the first nested group was invisible. That is how
`bv-logical` was measured as a leaf depending only on `errors`, `context`
and `handler`, when `Request` in fact carries a `Storage` handle. The
extraction was started in the wrong order and had to be backed out and
redone after `bv-storage`.

The working scanner counts braces, expands one level of nesting, and splits
`#[cfg(test)]` blocks out before counting. The corrected graph, which is
what the shipped order follows:

| crate | production deps (workspace only; `bv_crypto` predates this phase) |
|---|---|
| `bv-errors`, `bv-shamir`, `bv-context`, `bv-metrics` | none |
| `bv-storage` | errors, metrics, bv_crypto |
| `bv-logical` | errors, context, **storage** |
| `bv-audit` | errors, logical, storage |
| `bv-utils` | errors, shamir, storage, logical, bv_crypto |

`bv_crypto` already existed and has no workspace dependencies of its own, but
it is *below* `bv-storage` (the barriers use it) and below `bv-utils`. That
ordering was wrong in `scripts/publish-crates.sh`, which listed the new Tier 0
crates ahead of it; fixed in the same change.

#### What each inversion actually was

Four of the eight were not file moves. Recording them because the pattern
repeats in Phase 3:

- **`bv-metrics`.** `MetricsManager::new` called
  `crate::plugins::metrics::register` by name — one line, and the only
  thing keeping the metrics substrate out of Tier 0. Replaced by
  `register_collector`, which the two assembly points that build a manager
  call. The actix-web middleware stayed in `src/metrics` deliberately:
  `bv-storage` depends on `bv-metrics` for the cache counters, so anything
  in it lands under every leaf engine and actix must not.
- **`bv-storage`.** `TokenCache` named
  `modules::auth::token_store::TokenEntry`, pointing storage at the auth
  engine. The entry only ever exists in the cache as opaque serialized
  bytes, so `lookup`/`insert` became generic and the naming went away with
  no change to what is stored or to the four security invariants in
  `features/caching.md`. Separately, the backend and barrier tests needed
  `crate::test_utils`; the four fixtures they use moved into
  `bv_storage::test_support` behind a `test-support` feature that the root
  crate turns on through a dev-dependency, and `test_utils` re-exports them
  so no call site changed. The two tests that drive a *second vault
  process* through the `bvault` CLI could not travel and live in
  `src/storage_backend_tests.rs`.
- **`bv-logical`.** `Handler::post_config(Arc<Core>, Option<&Config>)` had
  **zero implementors** anywhere in the workspace, and its only caller
  discarded the error it always returned. That dead signature was the sole
  reason `Handler` named `Core` and the CLI's config parser, and
  `Request` holds an `Arc<dyn Handler>`. Deleting it is what made the
  extraction possible.
- **`bv-audit`.** The hard one, and the one this roadmap had wrong until the
  end — see the next section.

#### `bv-audit` was never unblocked by Phase 2

The table below (and the summary that used to head this file) said
`bv-audit` was "unblocked (Phase 2 done)" because it had stopped reaching
`crate::core::Core` directly. That was true and it was not the blocker.
The blocker is that `VaultCtx::audit_broker()` returns an
`Arc<AuditBroker>` — **the kernel contract and the audit subsystem named
each other**, so neither could become a crate while that held. Phase 2 did
not change this; it moved audit's one `crate::modules` constant into
`kernel_api`, which for these purposes made it slightly worse.

Cut by pushing audit *below* the kernel contract, in three moves:

1. `AuditBroker::new` took a `&dyn VaultCtx` to fetch one thing off it. It
   now takes the `BarrierView`. The `ErrBarrierSealed` check moved to
   `post_unseal`, its only caller, which is the code that actually knows.
2. `audit::sys_emit` — resolving a token through `TokenService` and
   fetching the broker off `VaultCtx` — stayed in the root crate. It is
   kernel glue, not audit. `src/audit/mod.rs` is now a shim over
   `bv_audit` plus that module, the same shape `src/metrics` took, so
   `bastion_vault::audit::*` paths are unchanged.
3. `NS_PATH_META` and its two siblings moved to `bv-logical`, next to the
   `Auth::metadata` map they key. `kernel_api::namespace` re-exports them,
   so the call sites Phase 2 created still resolve.

**Generalisation for Phase 3:** when two things name each other, look for
which of them is fetching a *handle* it only uses once, and which of them
is glue that belongs in the assembly layer. Both were true here.

#### The original plan, kept for the record

The original plan was:

> 1. `bv-errors` (fix the actix import first)
> 2. `bv-utils`, `bv-shamir`
> 3. `bv-logical`
> 4. `bv-storage` (+ `bv-cache` folded in) — this is the phase that moves
>    `hiqlite`, `diesel`, and `rusty-s3` out of the monolith's compile unit
> 5. `bv-audit`, `bv-metrics` (after their two inversions)

Steps 2–5 did not survive the corrected dependency table above, and the
revision that replaced them did not survive the *third* re-measurement
either — it kept `bv-logical` before `bv-storage`, and claimed `bv-audit`
was unblocked. Both are wrong; see the two sections above for what shipped
and why.

`bv-errors` is a hard prerequisite for everything, not a deferrable
tail-end change: a new crate cannot depend on the root crate, so no module
that references `crate::errors` can leave until `RvError` has left.

Re-export every moved path from `src/lib.rs` (`pub use bv_shamir as shamir;`)
so no call site outside the moved directory changes in this phase.

#### The test-scope hole this opened

A bare `cargo nextest run` covers only the **root package**, because this
workspace has one. That was invisible while all the code lived in the root
crate; the moment `src/shamir.rs` became `crates/bv-shamir`, its 21 tests
silently stopped running under `make test` (1145 → 1124). Every later
extraction would have done the same, quietly trading coverage for
modularity — the exact failure mode outcome #1 of this roadmap exists to
prevent.

Fixed by scoping `make test`, `make test-integration`, `make test-doc` and the
CI steps to `--workspace` minus the GUI and the vendored `ferro-*` crates —
stated as exclusions so a crate from a future phase is covered the day it
exists. This also picked up ~143 tests in the *pre-existing* crates
(`bv_crypto`, `bv-client`, the plugin crates) that had never run here either:
1145 → 1288, and doctests 15 → 17.

A separate `test-crates` target was tried first, on the theory that mixing the
crates in destabilised the suite. **That theory was wrong** and the measurement
is recorded here so it is not re-derived: three consecutive runs failed 1/0/2
tests at the wide scope and 0/0/3 at the root-only scope. The repo has a
pre-existing family of flaky timing-dependent tests
(`modules::auth::expiration::*`, the 20s window in
`metrics::system_metrics::test_sys_metrics`, the AppRole tidy race) that fail at
either scope. They are tracked separately and must not be papered over with
nextest `retries` — see `.config/nextest.toml`.

#### Lint scope is not inherited, and that is on purpose

Every extracted crate starts from clippy's defaults. `bv-logical`,
`bv-utils` and `bv-audit` each carry their own short `[lints.clippy]` block
listing only the lints their own code trips — all of which the root crate
already allows — rather than inheriting a `[workspace.lints]` block.

That is deliberate, and the reason is in the root manifest's own comment:
`await_holding_lock` was set to `"allow"` for years and hid a real deadlock
in the lease sweeper. It was caught only when `bv-context` was extracted and
stopped inheriting the allow. A workspace-wide lint block would give that
back. One nit was fixed rather than allowed on the way out (`use blake3;`,
which edition 2021 does not need).

#### The test-scope hole, revisited

The `--workspace` scoping described below held for all five new crates: unit
counts went 1289 → 1289 across every extraction, because each crate's tests
travel with it and nextest picks up the new member the day it exists. Two
things needed manual attention:

- **`.config/nextest.toml`'s `default-filter`** excluded the port-bound
  hiqlite tests by the path `storage::hiqlite::test::`. Those tests lost the
  `storage::` prefix when they changed crate, so the filter silently stopped
  matching and the run picked up 8 extra tests. Now matched with the prefix
  optional, and `make test-hiqlite` targets `-p bv-storage`.
- **Tests that cannot travel** — anything using `crate::test_utils`, which
  stands up a whole vault — were relocated into the root crate rather than
  deleted: `src/metrics/{http,system}_metrics_tests.rs`,
  `src/storage_backend_tests.rs`, and `src/audit/tests.rs`.

**Outcome vs. the expectation:** "the substrate stops recompiling on engine
edits" is now structurally true — 19,565 lines left the root compilation
unit — but it does not show up in `check-leaf`/`check-core`, because those
were already served by rustc's incremental cache within the single unit.
The win that *is* measurable is the other direction: a substrate edit no
longer rebuilds the monolith to be checked (0.78s vs ~8s). The real value
remains that Phases 3–4 are now possible.

### Phase 2 — Break the `Core` ↔ `modules` cycle — **done**

The crux. No files move; only the direction of dependency changes.

The plan below is kept as written, because the record of where it was wrong is
the useful part. What actually landed, and the four assumptions that did not
survive, are under "How the second half landed" onwards.

#### Do the inversion in-crate first; make it a crate second

`bv-kernel-api` cannot be created at the *start* of this phase, and the plan
below reads as though it can. The trait signatures name Tier 2 and Tier 0
types that have not been extracted yet — `VaultCtx::system_view()` returns
`Arc<BarrierView>` (`src/storage`), `router()` returns `Arc<Router>`
(`src/router`), `mounts_router()` returns `Arc<MountsRouter>` (`src/mount`).
A new crate holding those signatures would need all three as dependencies,
and `src/router` / `src/mount` are Tier 2 by this roadmap's own graph.

That is a sequencing problem, not a design problem, because **the crate is not
what breaks the cycle — the abstraction is.** So:

1. Define the traits in the monolith first (`src/kernel_api.rs`) and convert
   modules to `Arc<dyn VaultCtx>` there. The `Core` ↔ `modules` cycle is cut
   at that point, which is what unblocks Phase 3, `bv-logical` and `bv-audit`.
2. Move `src/kernel_api.rs` into `bv-kernel-api` later, once `bv-storage`
   exists and `router`/`mount` have moved into `bv-core`. That move is then a
   mechanical file move of the kind Phase 1 step 2 was supposed to be.

Doing it the other way round means blocking the whole phase on the extraction
order it was meant to enable.

Then, as originally planned:

1. Define the traits the measurements above identified:
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

#### Step 3 is not step-shaped: measured cost of the `Module` trait flip

`VaultCtx` + `impl VaultCtx for Core` **is landed** (`src/kernel_api.rs`), and
it is additive: no call site changed, so it verified on its own.

Step 3 — "change engine signatures from `Arc<Core>` to `Arc<dyn VaultCtx>`,
module by module, cheapest first" — was then attempted and reverted, so the
cost below is measured rather than guessed. **It cannot be done module by
module, and it is not the phase's second step: it is the phase.**

Two signatures make it atomic rather than incremental:

```rust
// src/modules/mod.rs — all 26 `impl Module for` blocks
async fn init(&self, _core: &Core)  -> Result<(), RvError>;
fn setup(&self, _core: &Core)       -> Result<(), RvError>;
fn cleanup(&self, _core: &Core)     -> Result<(), RvError>;

// src/core.rs:44 — every engine's mount closure is one of these
pub type LogicalBackendNewFunc = dyn Fn(Arc<Core>) -> Result<Arc<dyn Backend>, RvError> + Send + Sync;
```

Flipping the `Module` trait alone took the tree from 58 errors to 17 across
four mechanical passes, and the 17 that remained are the real content:

| what | count | nature |
|---|---|---|
| missing `use crate::kernel_api::VaultCtx` | 47 | mechanical, two passes |
| `core.<field>` → `core.<method>()` | 45 | mechanical (incl. 62 multi-line `core\n.module_manager`) |
| `fn new(core: &Core)` store constructors to widen | 21 | mechanical — they only need `system_view()` + `router()` |
| accessors still missing from `VaultCtx` | 5 | `cache_config`, `auth_handlers`, `require_machine_identity` |
| `&Arc<Core>` passed where `&dyn VaultCtx` wanted | 9 | needs `as_ref()`; `&Arc<T>` does not coerce to `&dyn U` |
| **`core.self_ptr.clone()` into a `Weak<Core>` field** | **2** | **the wall** |

Those last two are why the flip cannot land on its own. `ExpirationManager`,
`PolicyStore`, `TokenStore` and their peers keep a `core: Weak<Core>`
back-reference obtained from `core.self_ptr`, and `self_ptr` is deliberately
*not* on `VaultCtx`. Giving them a kernel handle means `Weak<dyn VaultCtx>`
(the coercion is legal — `Weak<T>` is `CoerceUnsized`), which retypes the
field, which drags in every use of it:

| | count |
|---|---|
| `Arc<Core>` occurrences in `src/` | **353** |
| `Weak<Core>` / `Arc<Core>` struct fields in `src/modules` | **118** |
| `self.core` uses in `src/modules` | **171** |

So the honest sequencing is a single atomic change covering the `Module`
trait, `LogicalBackendNewFunc`, and the ~353 `Arc<Core>` sites together —
*not* steps 3 and 4 as separate items, and not "cheapest engine first".
Budget it as its own multi-day PR whose gate is the full suite, and expect
`VaultCtx` to grow ~5 more accessors on the way.

Two smaller corrections to the numbers above while re-measuring:

- The self-lookups are **20**, not ~12: `RustionModule` 10, `AppRoleModule` 7,
  `NotificationsModule` 2, `SshBrokerModule` 1. All four are genuinely
  self-lookups (each resolved from inside its own directory), so the
  "kernel of five" claim holds — `get_module::<T>()` has eight concrete
  targets, and the three extra ones are these.
- The `get_module` work is **~101** production call sites, not 43. The 43
  counted only those spelled literally as `core.module_manager.get_module`.

#### How the second half landed

Steps 3 and 4 were done first (see above). This section records the rest —
step 1's five store traits and the `ModuleRegistry` — as it actually shipped,
because three of the plan's assumptions did not survive contact.

**The registry is not a registry of modules; it is a registry of
capabilities.** The plan has `ModuleRegistry` "replacing
`ModuleManager::get_module`'s `Arc::downcast` with typed accessors", which
reads as `registry.identity() -> Arc<IdentityModule>`. That would have kept
every engine naming `IdentityModule`, which is the whole problem. What landed
instead is [`KernelServices`](../src/kernel_api/services.rs): each provider
registers *itself as a trait object* at module installation, and consumers ask
[`VaultCtx`](../src/kernel_api/ctx.rs) for the capability. No name, no
downcast, no concrete type. `Module` grew one hook, `register(self: Arc<Self>,
&KernelServices)`, because publishing a trait object needs an `Arc<Self>` and
neither `init` nor `setup` has one.

**Ten slots, not five.** The plan's five (`TokenStore`, `IdentityStore`,
`PolicyStore`, `NamespaceRegistry`, `ResourceGroupStore`) are there, split
slightly differently:

| slot | file | why |
|---|---|---|
| `IdentityService` | `kernel_api/identity.rs` | entities, group policy expansion, ownership, user audit |
| `TokenService` | `kernel_api/auth.rs` | token lookup + revoke |
| `AuthMountRegistry` | `kernel_api/auth.rs` | separate from tokens: a credential backend must be able to mount itself without being able to resolve other people's tokens |
| `PolicyGate` | `kernel_api/policy.rs` | the three authorization *questions*, never an `ACL` |
| `NamespaceRegistry` | `kernel_api/namespace.rs` | resolution, login binding, per-namespace routers, quotas |
| `ResourceGroupIndex` | `kernel_api/resource_group.rs` | the asset-group reverse index |

plus four in [`kernel_api/engines.rs`](../src/kernel_api/engines.rs) for the
Tier 3 ↔ Tier 3 edges below: `LoginClassPolicy`, `ConnectMfaGate`, `TotpMfa`,
`NotificationSink`. Those are **engine** contracts, not kernel contracts, and
they live in their own file so they can move to a `bv-engine-api` crate as a
file move rather than a rewrite.

**The traits carry operations, not store handles.** `IdentityService` does not
return `Arc<OwnerStore>`; it has `rename_object(kind, old, new, ns, actor)`.
That is what makes the boundary real: `bv-kernel-api` cannot depend on
`bv-kernel`, so anything crossing has to be owned data or a narrow answer. It
also deleted code — the resource engine's rename used to inline twenty lines of
namespace-key scoping and share/owner moving, all of which required it to know
how owner records are keyed.

#### Step 2 (the self-lookups): shared slots, not `Weak<Self>`

The "Re-measured" block above proposed `Weak<RustionModule>` captured at
registration. The shipped fix is narrower and needs no self-reference at all:
the engine's late-bound *stores* move into one `Arc<RustionStores>` shared
between the module, the logical backend, and the four background tasks. Same
for `notifications::ServiceSlot` and `ssh_broker::PolicyStoreSlot`.

The block was right that the lookup exists because the handle must be **late**
(the stores are created in `Module::init`, at unseal, and a sealed vault has
none) and wrong that this needs a handle to the *module*. It never did — it
needed a handle to the slot.

Every **production** self-lookup is gone: Rustion 9, notifications 1,
ssh-broker 1. The 7 `AppRoleModule` ones the block already identified as
test-only stay with their tests, alongside 4 in `files` and 1 in `rustion` —
12 in total, and all 12 are in `#[cfg(test)]` modules that use
`crate::test_utils`, which is what actually pins them to the root crate. A
`SelfRef<T>` helper was written for the `Weak` approach and deleted unused.

#### Tier 3 ↔ Tier 3: three real edges, not a three-cycle

The "engines are not leaves" block above lists five cross-engine edges and two
cycles. Re-measured with comments stripped, **three of the five were doc
comments only** (`totp -> credential`, `ssh_broker -> rustion`, and the
`credential -> resource` half). The real graph was a DAG:

```
credential -> totp          (mfa::verify_code, mfa::normalize_mount)
resource   -> ssh_broker    (EffectiveLoginClass, LoginClass)
rustion    -> resource      (connect_mfa::enforce)
plugins    -> notifications (NotificationService)
```

So there was no unresolvable cycle — but each edge still pinned two engines
into one compile unit, so each got a trait at the boundary anyway. Two of them
shrank on the way across: the resource engine reads two of `EffectiveLoginClass`'s
six fields, so `LoginClassVerdict` carries two; the notification sink speaks
JSON, which the plugin ABI already was on both sides.

`resource::connect_mfa::resource_has_gated_profile` moved out of the Rustion
transport, where it had been written and did not belong — the gate is the
resource engine's, and the second transport to need it would have copied it.

#### Also inverted, because the same edge pointed the other way

Three places had `Core` naming its modules rather than the reverse. They are
the same dependency and they had to go too:

- **`Core::post_unseal` named six engines' schedulers** by path
  (`pki::scheduler`, `rustion::{probe,poller,telemetry,attest_timer}`,
  `ldap::scheduler`, `files::scheduler`, plus the system reconciler and the
  cert-lifecycle scheduler). Replaced by `Module::start_background`, which the
  module manager calls on the whole set.
- **`Core::flush_caches` named the policy and auth modules.** Replaced by
  `Module::flush_caches`.
- **`src/audit/entry.rs` reached into `crate::modules` for one constant**
  (`NS_PATH_META`) — a cross-layer wart this roadmap tracked separately, in the
  table under "Cross-layer warts to fix first". The namespace token-metadata
  keys and the pure namespace-path helpers (`namespace_header_from_map`,
  `normalize_path`, `validate_segment`, `stamp_binding`,
  `binding_from_metadata`, `writer_namespace_path`) moved to
  `kernel_api::namespace` and are re-exported from their old homes, so no call
  site outside those files changed. `MAX_LEASE_DURATION_SECS` and
  `caller_audit_actor` moved for the same reason.

#### Tiering: what still names what, and why that is the end state

`VaultCtx::module_manager()` is **gone**. The module set is reachable only
through `Core::module_manager()`, an inherent method — so the type system now
enforces the split rather than a convention:

| tier | may name | count |
|---|---|---|
| Tier 3 engines, `src/audit`, `src/plugins` | Tier 0 + `kernel_api` | **0** `get_module`, **0** `Core` |
| Kernel tier (`auth`, `identity`, `policy`, `namespace`, `resource_group`, `system`) | each other + `Core` | 79 `get_module` |
| Assembly (`core.rs`, `src/http`) | everything | 10 `get_module` |

The kernel tier's 79 are not debt: those six modules ship together as
`bv-kernel` by this roadmap's own graph, and they *are* the kernel. The
remaining `core.rs` → `crate::modules` edges (namespace ×5, identity, system,
auth) are the `bv-core` ↔ `bv-kernel` entanglement the target graph already
predicts — the request pipeline calls into namespace rewriting, token binding
and quota enforcement on every request. Resolving that is a Tier 2 question for
whichever phase extracts those two crates, not a Phase 2 one.

#### What Phase 2 did not move

- **Build time.** No crate was created, so nothing was expected to move, and
  nothing did — see the row appended to
  [docs/build-timings/baseline.md](../docs/build-timings/baseline.md). Phase 2
  buys the *ability* to split, which is Phase 3's payoff. Attributing any
  speedup to this phase would be wrong.
- **Behaviour.** `make test-all`, `make plugins-test`, `make test-cucumber` and
  `make test-hiqlite` are green with zero changed test outcomes (1289 unit,
  1358 integration, 8 hiqlite, 8 cucumber scenarios). That was the phase's own
  gate: "this phase should land with **zero** change in test outcomes; if any
  test changes, the abstraction is wrong."
- **12 test-only `get_module` sites in Tier 3** (`approle` ×7, `files` ×4,
  `rustion` ×1). Left deliberately: every one of them also calls
  `crate::test_utils::new_unseal_test_bastion_vault`, so they cannot travel
  into an engine crate regardless — they have to become `tests/` binaries,
  which is Phase 3 work and is exactly what Phase 3 does with the PKI suite.

### Phase 3 — Engines out, starting with PKI — **done**

> **"Unblocked" was half true, and the missing half is a whole crate.** Phase 2
> left every Tier 3 engine free of `Core` and of its siblings, which is what
> this section measured. It did not leave them free of the *root crate*: every
> engine implements `crate::modules::Module` and holds an
> `Arc<dyn crate::kernel_api::VaultCtx>`, and a crate cannot implement a trait
> defined in the crate above it. So Phase 3 does not open with PKI. It opens
> with **`bv-kernel-api`** — the Tier 1 crate Phase 2 deliberately deferred —
> and nothing else could have gone first. See "Step 0" below.

**Now unblocked, and the extraction order is free.** Phase 2 left every Tier 3
engine with zero production references to `Core` and zero to any sibling
module, so the engines form no graph among themselves: any order works, and
each extraction is a file move plus a manifest. The order below is therefore a
value judgement, not a constraint.

Order by (churn × size) ÷ coupling. PKI first, and not narrowly:

- 15,127 lines, 96 of the last 300 commits
- **19 of the 30 `tests/` binaries** are PKI (`test_pki_*.rs`,
  `test_cert_lifecycle_*.rs`, `test_rustion_master_pki_issue.rs`)
- 0 of its 39 files touch `Core`

Move `tests/test_pki_*.rs` into `crates/bv-engine-pki/tests/`. Those 19
binaries then link the PKI crate plus substrate instead of the 245 MB
monolith rlib — which is what makes them cheap enough for CI to run at
all. **This single extraction closes most of the current integration-test
coverage gap.**

> **The test move does not work, and the reason is worth keeping.** All 23
> candidate binaries (19 `test_pki_*`, 3 `test_cert_lifecycle_*`,
> `test_rustion_master_pki_issue`) open with `BastionVault::new(...)`, unseal,
> and mount `pki/` through the real mount table — they are testing the engine
> *through the server*, which is most of their value. Moving them into
> `crates/bv-engine-pki/tests/` would mean a dev-dependency on `bastion_vault`
> (legal — cargo allows dev-dependency cycles) that links exactly the same
> rlib, so it buys nothing; and rewriting them to drive a bare
> `LogicalBackend` would delete the routing, mount and token coverage that
> makes them integration tests rather than unit tests.
>
> So the "19 binaries get cheap" mechanism is wrong, and **the claim that this
> single extraction closes the coverage gap is wrong with it.** What the split
> actually buys CI is the Phase 5 mechanism, not this one: a PKI change now
> invalidates `bv-engine-pki` rather than the root crate, so a path-filtered
> matrix can run *only* the PKI binaries and skip the rest. The gap closes in
> Phase 5, on the foundation Phase 3 lays — not here.

Then, in descending order: `rustion`, `files`, `transit`, `ssh` +
`ssh_broker`, `totp`, `ldap`, `notifications`, `cert_lifecycle`, `kv` +
`kv_v2`, `resource` + `resource_group`.

Finally split `credential/` (22,139 lines, 58 files, the single largest
directory and highest-churn area) into one crate per backend. Do it last: it
was the most entangled tier-3 code — auth, identity, namespace and totp all
reached through concrete types — and it benefits most from Phase 2 having
settled. Those edges are now `kernel_api` traits, so the split is mechanical;
what remains is the test scope, since its `#[cfg(test)]` modules use
`crate::test_utils` and have to become `tests/` binaries first.

**Expected:** a PKI-only change compiles PKI plus the facade, not 173k
lines. Target: the 35.7 s test-binary rebuild drops to single digits for
a leaf-engine edit.

#### Step 0 — `bv-kernel-api`, and why it carries `router`/`mount`/`dos`/`stats`

Phase 2's own note says the crate can be created "later, once `bv-storage`
exists and `router`/`mount` have moved into `bv-core`". `bv-storage` exists.
`bv-core` does not, and waiting for it would have inverted the whole
decomposition: `bv-core` is Tier 2, Phase 4 work, and it cannot be extracted
before the engines it currently compiles alongside.

So the split was made on a different line — not "which tier does the roadmap
assign this file", but **"does a `VaultCtx` signature name it"**:

| type | named by | engine call sites |
|---|---|---|
| `Router` | `VaultCtx::router` | 8 (`totp`, `resource` ×4, `rustion` ×2, `credential`) |
| `MountsRouter` | `VaultCtx::mounts_router` | 4 (`pki`, `ldap`, `files`, `cert_lifecycle` schedulers) |
| `MountsMonitor` | `VaultCtx::mounts_monitor` | 0, but returned by the trait |
| `DosGuard` | `VaultCtx::dos_guard` | 0, but returned by the trait |
| `DashboardStats` | `VaultCtx::stats` | 0, but returned by the trait |
| `MountEntryHMACLevel` | `VaultCtx::mount_entry_hmac_level` | 0, but returned by the trait |
| `LogicalBackendNewFunc` | `VaultCtx::add_logical_backend` | every engine's mount registration |

A crate holding only the traits would need all seven as dependencies anyway,
so "only the traits" was never available. The alternative — another trait
layer between the kernel contract and the mount table — buys nothing: the
mount table *is* the engine-facing view of the routing tier, and `Core`'s own
mount management is already excluded from it.

What stayed in the root crate, and why:

- **`impl VaultCtx for Core`** → `src/kernel_impl.rs`. `Core` is Tier 2 and
  `bv-kernel-api` must not name it. Implementing a foreign trait for a local
  type is exactly what the orphan rule allows, so this cost nothing — unlike
  `bv-errors` in Phase 1, where the orphan rule cost 200 sites.
- **`impl Core { mount, unmount, remount, unload_mounts }`** → `src/mount.rs`,
  now a 200-line file over a `pub use bv_kernel_api::mount::*`. These are the
  *management* operations, deliberately absent from `VaultCtx`.
- **`dos::middleware`** — actix, which must not reach a leaf engine. Same
  reason `metrics`' middleware stayed behind in Phase 1.
- **`dos::store`'s tests** → `src/dos/store_tests.rs`, because they stand up a
  whole vault through `crate::test_utils`. Third instance of the Phase 1
  pattern.

Three edges had to be inverted or moved first, all of them small:

- **`mount.rs` → `crate::plugins`** — the wart this roadmap has tracked since
  the "Cross-layer warts" table. The mount table stripped `plugin:` off a
  mount type and called the plugin runtime's factory by name. Now the runtime
  registers a `DynamicBackendResolver` from the assembly layer and the mount
  table only asks. This was the last wart on that list.
- **`MountEntryHMACLevel`** moved out of `cli::config` (re-exported from it),
  and **`LogicalBackendNewFunc`** out of `core.rs` (likewise). Both are named
  by the trait, and both would otherwise have dragged the CLI and `Core` under
  every engine.
- **`MountsMonitor::start` built an `actix_rt::Runtime`** to block on the
  mount-table poll. `actix_rt::Runtime` is `tokio`'s current-thread builder
  plus a `LocalSet`; the monitor's future spawns nothing and is `Send`, so the
  `LocalSet` bought nothing and the actix dependency bought a leaf engine
  actix. Replaced with the tokio builder directly.

**Measured:** `src/` goes 154,373 → 151,070 lines and the new crate is 3,552,
so ~250 lines of shim and relocated tests came back — the cost of keeping
`bastion_vault::{mount,router,stats,dos,kernel_api}::*` resolving unchanged.
`cargo check --workspace` and the full unit suite are unchanged.
#### What Phase 3 shipped

Twenty-two crates: `bv-kernel-api` (Tier 1) plus twelve engines and nine auth
crates.

| crate | lines | note |
|---|---|---|
| `bv-engine-pki` | 15,127 | first out; owns the name `storage`, so nine files import `bv_storage::StorageEntry` directly |
| `bv-engine-rustion` | 11,613 | four detached background tasks; its master-store tests came *back* into the crate once they turned out to need only a `bv-storage` fixture |
| `bv-auth-approle` | 6,849 | → `bv-auth-ferrogate` (machine binding) |
| `bv-engine-files` | 4,947 | `files_smb` / `files_ssh_sync` forwarded from the root |
| `bv-auth-ferrogate` | 4,044 | the `ferro-*` SDK, from a second private registry |
| `bv-auth-saml` | 3,868 | keeps `sha1`/`sha2` pinned at 0.10 for XML-DSig |
| `bv-engine-resource` | 3,427 | provides `ConnectMfaGate`, consumes `LoginClassPolicy` |
| `bv-engine-transit` | 3,155 | `transit_byok` / `transit_pqc_hybrid` forwarded; `x25519-dalek` left the root |
| `bv-engine-ssh` | 2,935 | `ssh_pqc` forwarded |
| `bv-auth-userpass` | 2,881 | → `bv-auth-fido2` (passkey routes) |
| `bv-engine-ldap` | 2,736 | |
| `bv-auth-fido2` | 2,182 | |
| `bv-engine-notifications` | 2,025 | both ends of the plugin boundary, naming neither |
| `bv-auth-oidc` | 1,804 | |
| `bv-engine-totp` | 1,684 | provides `TotpMfa` |
| `bv-engine-cert-lifecycle` | 1,552 | also owns the name `storage` |
| `bv-engine-kv` | 1,323 | `v1` + `v2`, one crate |
| `bv-engine-ssh-broker` | 1,291 | provides `LoginClassPolicy` |
| `bv-auth-audit` | 257 | the login-audit store five backends write and the kernel tier reads |
| `bv-auth-cert` | 180 | the retired backend, kept as a landing site |

**Measured outcome:**

| | before Phase 3 | after |
|---|---|---|
| `src/` (the root compilation unit) | 154,373 lines | **84,827** |
| workspace members | 20 | **42** |
| direct dependencies of `bastion_vault` | — | **26 fewer** |
| unit test binaries | 19 | **39** |
| unit suite wall clock | 180s | **91s** at the twelve-engine mark |
| unit / integration / doctests | 1289 / 1358 / 17 | **unchanged** |

The 26 dependencies that left the root manifest with their code: `base32`,
`blake3`, `cms`, `const-oid`, `flate2`, `hickory-resolver`, `hyper-rustls`,
`hyper-util`, `image`, `ldap3`, `openidconnect`, `pkcs12`, `pkcs5`, `prost`,
`qrcode`, `quick-xml`, `rsa`, `russh`, `russh-sftp`, `sha1`, `sha1-saml`,
`sha2-saml`, `subtle`, `tonic`, `tonic-prost`, `url`.

#### The alias preamble, and why the extraction stayed a file move

Each engine crate's root carries a **private** alias block:

```rust
use bv_context as context;
use bv_errors as errors;
use bv_kernel_api as kernel_api;
use bv_logical as logical;
use bv_storage as storage;
use bv_utils as utils;
```

so `crate::errors::RvError` and `crate::logical::Path` keep resolving inside
the new crate and not one engine file's imports changed. Private, so none of
it reaches the crate's public API. Two consequences worth knowing:

- **An engine that owns one of those names wins it.** `pki` and
  `cert_lifecycle` both have a `storage` module; the alias is omitted there and
  the handful of files wanting the substrate's `Storage`/`StorageEntry` name
  `bv_storage` directly. The collision is a compile error, not a silent shadow.
- **`use super::*` in a test stops seeing the parent's imports.** A glob sees a
  module's *private* `use` statements only from inside the same crate. Every
  lifted test block therefore needed the parent's import list written out.

#### Three inversions, and one that was wrong twice

- **`notifications` → `plugins`.** `channel.rs` called `PluginCatalog` and
  `invoke_active_plugin` by name; the runtime holds an `Arc<dyn VaultCtx>` and
  reaches the mount table, so it is above the engines. Now `PluginHost` in
  `kernel_api::engines`, registered by the assembly layer because the runtime
  is not a `Module`. It narrows on the way across the way `LoginClassVerdict`
  did: a manifest becomes five strings.
- **The CLI login handlers were not engine code.** `token/cli.rs`,
  `userpass/cli.rs` and `cert`'s inline `cli` implement `LoginHandler` — read a
  password off the terminal, POST through the HTTP client. Leaving them would
  have put `crate::api`, `rpassword` and stdin under every auth crate. They are
  `src/cli/command/login_handlers.rs` now.
- **`credential/token` was not a backend.** One line: `pub mod cli;`. Token
  auth *is* the kernel's `auth` module. There is no `bv-auth-token`.

And the one to remember: **`actix_rt::spawn` is `tokio::task::spawn_local`,
not `tokio::task::spawn`.** The AppRole tidy endpoint was converted to `spawn`
on the reasoning that the future is `Send` and actix-rt only aliases tokio's
`JoinHandle`. Both premises are true and the conclusion is still wrong —
moving the routine off the caller's thread onto the runtime pool changes the
interleaving, and the tidy *race* test caught it (2,988 accessors where 6,064
were expected). `spawn_local` is the faithful translation. The same reasoning
applied to `MountsMonitor::start` *is* sound, because that one is `block_on`,
not a spawn: the future runs on the calling thread either way.

#### Four feature flags had quietly become no-ops

`ssh_pqc`, `pki_pqc_composite`, `transit_byok` and `transit_pqc_hybrid` were
declared `= []` in the root manifest while the `cfg` gates they drive
travelled into the engine crates — so an operator's `--features ssh_pqc` would
have silently built without ML-DSA SSH CA support. They now forward to the
engine crate, and the optional-feature build is verified. `files_smb` and
`files_ssh_sync` forward the same way, with their optional deps moved to
`bv-engine-files`.

#### Tests that could not travel

`crate::test_utils` stands up a whole vault and is a `#[cfg(test)]` module of
the root crate, so anything using it stays in `src/engine_tests/` — the third
instance of the Phase 1 pattern, after `storage_backend_tests.rs` and
`dos/store_tests.rs`. The split is **per test block, not per file**: a block
that only needs `super::*` stayed with its engine. Where a lifted block needed
a private item, the item became `pub` with a comment saying why
(`files::sha256_hex`, `approle::SECRET_ID_PREFIX`,
`resource::connect_mfa::ticket_key`, `userpass::{is_plausible_email, now_secs}`,
`rustion::namespace_sub_request_prefix`) — except where splitting the block was
better, which is what happened to `connect_mfa`'s pure tests.


### Phase 4 — Assembly split — **done**

The plan, kept because the record of where it was wrong is the useful part:

> - `bv-server` — `src/http`, taking actix out of every engine's tree
> - `bvault-cli` — `src/cli` (111 commits; deserves to build alone)
> - `bastion_vault` becomes a thin facade: re-exports plus the registration
>   list that wires engines into a `ModuleRegistry`
> - `gui/src-tauri` keeps depending on the facade at first; once the engine
>   crates are stable, narrow it to `bv-core` plus the engines the embedded
>   vault actually mounts. **This is the biggest single GUI-CI win** —
>   today `gui/src-tauri/Cargo.toml` carries
>   `bastion_vault = { path = "../.." }`, so every server-side change
>   rebuilds the Tauri host.

#### The tier is above the library, not below it

Every phase so far extracted crates *downward* — a new crate the root crate
depends on. Phase 4 cannot: `src/http` names `Core`, `modules`, `plugins`,
`exchange`, `scheduled_exports` and `backup`, and `src/cli` names all of those
plus `BastionVault` itself. Extracting them downward would require `bv-core`
and `bv-kernel` (Tier 2) to exist first, and **those are in no phase** — the
target graph lists them but neither Phase 3 nor Phase 4 creates them.

That is not a gap in the plan so much as a misreading of what the assembly
layer *is*. The HTTP surface and the CLI are not libraries the vault depends
on; they are the things that mount it. So both went **above**
`bastion_vault`, which is exactly where the target graph's Tier 4 puts them —
and the phase needed no Tier 2 extraction at all.

Consequence for the third bullet: `bastion_vault` is **not** a thin facade,
and could not become one in this phase. It is 65,703 lines — the kernel
(`core.rs`, `modules/`, `module_manager`) plus the subsystems the assembly
layer mounts (`plugins`, `exchange`, `hsm`, `backup`, `scheduled_exports`,
`api`). Thinning it is the `bv-core` / `bv-kernel` split, and that is a
separate phase this document should stop implying happens for free.

#### The two crates had to land together

`src/cli/command/server.rs` is the actix wrap site: the one place that builds
an `App` out of the HTTP routes and middleware. So `bvault-cli` depends on
`bv-server`, and leaving `src/cli` in the library while `src/http` moved above
it is a **normal dependency cycle** — `bastion_vault` → `bv-server` →
`bastion_vault` — which cargo rejects. Same for the `bvault` binary: a
`[[bin]]` shares its package's `[dependencies]`, so it could not stay in the
root package either, and its deb/rpm packaging metadata travelled with it.

| crate | lines | note |
|---|---|---|
| `bv-server` | 9,049 | `src/http` + the two actix middleware layers + the test harness |
| `bvault-cli` | 9,560 | `src/cli` + the `bvault` binary + its Linux packaging metadata |

**Measured outcome:**

| | before Phase 4 | after |
|---|---|---|
| `src/` (the root compilation unit) | 84,827 lines | **65,703** |
| workspace members | 42 | **44** |
| `actix-web` / `actix-tls` in `bastion_vault` | yes | **gone** — `cargo tree -p bastion-vault-gui -i actix-web` finds no such package |
| unused direct deps in our crates (`make deps-unused`) | 9 | **0** |
| unit / integration / doctests | 1289 / 1358 / 17 | **unchanged** |
| unit test binaries | 39 | **41** |

The actix row is the phase's point. `gui/src-tauri` path-depends on
`bastion_vault`, so until now the Tauri host compiled a web framework it never
serves from. Nine dependencies left the root manifest with the CLI — `clap`,
`env_logger`, `prettytable`, `rpassword`, `serde_yaml`, `toml`, plus
`ciborium`, `ipnetwork` and `uuid`, which **Phase 3's engine moves had already
orphaned without anyone noticing**; `make deps-unused` was failing on them and
is green again.

#### Four things that had to move before the split would hold

- **`cli::config::Config` was never CLI code.** It is the *server's*
  configuration model — `core.rs`, `modules::auth`, `src/http` and
  `BastionVault::new` all name it. It is `bastion_vault::config` now. This was
  the single edge pinning the command-line layer into the library.
- **`src/api/sys.rs` named `http::sys::InitRequest`.** A wire shape belongs
  with the client that serializes it, not the server that deserializes it, so
  `InitRequest` moved down into `api::sys` and `bv-server` re-exports it.
- **`ferrogate_mia` was not command-line code either.** 784 lines speaking
  length-delimited CBOR over a Unix socket, wanted by three callers — the
  `bvault ferrogate` subcommands, the Tauri host, and the approle engine
  tests. Leaving it in the CLI would have made the **GUI depend on the CLI**,
  dragging actix-web and clap back into the Tauri host and inverting the whole
  point of the phase. It is `bv_auth_ferrogate::mia` now.
- **The two actix middleware layers went up, not down.** Phase 1 refused to
  let `metrics::middleware` travel into `bv-metrics` and Phase 3 refused to let
  `dos::middleware` travel into `bv-kernel-api`, both because actix must not
  reach a leaf engine. Neither was ever going to find a home below; Phase 4 is
  where they get one above, as `bv_server::middleware::{dos, metrics}`.

#### The dev-dependency cycle, and why it is the right shape

`test_utils::TestHttpServer` runs an **in-process** actix server configured by
`http::init_service` — so it had to travel up into `bv-server` with the routes
it serves. But ~50 root-crate tests drive it, and the whole point of Phase 1's
"test-scope hole" section is that extractions must not quietly cost coverage.

Resolved with the arrangement cargo explicitly permits:

- `bv-server` → `bastion_vault` is a normal dependency.
- `bastion_vault` → `bv-server` is a **dev**-dependency, with
  `features = ["test-support"]`. Dev-dependency cycles are legal.
- `bastion_vault::test_utils` is `#[cfg(any(test, feature = "test-support"))]`
  and re-exports `TestHttpServer` from `bv_server` under plain `#[cfg(test)]`.

So not one of the ~50 call sites that say `crate::test_utils::TestHttpServer`
changed, and a consumer who enables `test-support` gets the vault fixtures
without getting a web server. Same shape `bv-storage` used for its backend
fixtures in Phase 1, one tier up.

**The cycle has a measured cost, and it landed on the plugin tests.** Pulling
`bv-server` into the root crate's *test* build pulls actix-web and ureq with
it: the `bastion_vault` lib-test binary went **213 MB → 227 MB**. That is
invisible everywhere except `src/plugins/process_runtime.rs`, whose seven tests
each read the entire test binary into a `Vec<u8>`, write a copy to a temp dir,
spawn it and drive a JSON-RPC handshake against a 30s deadline. At 227 MB,
copying that while ~75 sibling `plugins::` tests compete for disk was enough to
blow the deadline — 3 to 6 of them failed under `make plugins-test` while the
same seven passed in 16s run alone.

The deadline is `DEFAULT_INVOKE_TIMEOUT`, a **production** constant governing
how long the host waits on a plugin. Relaxing it to make tests pass would have
traded a real operational bound for a green run. The fix is scheduling:
`threads-required = "num-cpus"` in `.config/nextest.toml` makes each of the
seven take the whole runner, so they are serial against everything rather than
only against each other. `make plugins-test` went from 3–6 failures in 153s to
**82/82 in 21s** — making them exclusive was faster, not slower, because the
contention was the cost.

**`get_project_binary_path` had to stop trusting `CARGO_MANIFEST_DIR`.** It
resolved `target/debug/bvault` relative to that variable, which was the repo
root while there was only one package running tests. Three packages run these
fixtures now and cargo sets it per-package, so it is derived from
`current_exe()` — the test binary sits at `<target>/<profile>/deps/`, whose
grandparent is the profile directory — which also honours `CARGO_TARGET_DIR`.

#### The brace-import trap, for the fourth time

This document has now recorded three separate measurement errors caused by
regexes that cannot see `use crate::{ ... }`. Phase 4 made it four: a
`s/crate::cli::/crate::/g` pass over the moved CLI reported zero remaining
matches while **66 sites survived**, every one of them a `cli::` entry nested
inside a brace group where the literal string `crate::cli` never appears.

Worse, the fix for it over-corrected: splicing `http::` groups up a level also
ate `actix_web::{..., http::{header, StatusCode}, ...}` in six files, because
that `http::` also starts a path segment. Both were caught by the compiler
rather than by a grep.

**The rule this document keeps re-learning, stated once more:** never rewrite
an import with a line-oriented regex. Parse the use-tree by counting braces —
and when hoisting a segment, check what the *enclosing* path is, not just the
segment. The scanner in "Phase 1 § the third measurement error" does the first
half; Phase 4 needed the second.

#### Two name collisions, resolved the opposite way to Phase 3

`bv-server` has route modules called `logical` and `metrics`, and it also
needs `bastion_vault::logical` and `bastion_vault::metrics`. Phase 3 hit this
with `bv-engine-pki`'s `storage` module and let the engine win the name,
naming `bv_storage` directly at the few sites that wanted the substrate. Here
the substrate is wanted at far more sites than the routes are, so the routes
were renamed `logical_routes` and `metrics_routes` instead. Either resolution
works; the collision is a compile error, never a silent shadow.

#### What Phase 4 did not do

- **`bastion_vault` is not a facade.** See above — that is the `bv-core` /
  `bv-kernel` split, which no phase currently owns.
- **`gui/src-tauri` still depends on the root crate.** It stops building
  actix-web, actix-tls and the CLI's nine dependencies, which is the win that
  was actually available; narrowing it to `bv-core` plus the engines it mounts
  needs Tier 2 to exist.
- **`actix-rt` stays in the root crate**, and is production code:
  `ExpirationManager::start_check_expired_lease_entries` blocks a dedicated
  thread on an `actix_rt::Runtime`. That is tokio's current-thread builder plus
  a `LocalSet`, so it *looks* like the `MountsMonitor::start` swap Phase 3
  made — but proving the swept future never spawns a local task means tracing
  `revoke_lease_id` through the whole lease graph, and Phase 3 already recorded
  one wrong conclusion from exactly this reasoning (the AppRole tidy race).
  Behaviour preservation won. It is a small crate and not a web server.
- **Neither Tier 4 crate is published.** Both carry
  `publish = ["uox-bastionvault"]`, but each depends on `bastion_vault`, which
  is unpublishable while the `[patch.crates-io]` forks stand. They are
  documented as blocked in `scripts/publish-crates.sh` rather than added to its
  `CRATES` list, which would only make `crates-publish` fail.
- **The deb/rpm packaging is untested here.** The metadata moved to
  `crates/bvault-cli/Cargo.toml` with relative asset paths rewritten
  (`../../installers/...`) and the Makefile now passes `-p bvault-cli` to
  `cargo deb` / `cargo generate-rpm`. Neither tool is installed on the
  development host and both target Linux, so this is **reasoned, not
  verified** — `make linux-cli-packages` is the check, and it should be run
  before the next release cut.

### Phase 4.5 — The Tier 2 split — **done**

The crate pair the target graph named from the first draft — `bv-core` and
`bv-kernel` — and that no numbered phase ever scheduled. Phase 3 was engines,
Phase 4 was assembly, and Tier 2 fell between them.

#### The cycle Phase 2 measured and deferred

Phase 2 ended by naming this exactly: "the remaining `core.rs` →
`crate::modules` edges (namespace ×5, identity, system, auth) are the
`bv-core` ↔ `bv-kernel` entanglement the target graph already predicts …
Resolving that is a Tier 2 question for whichever phase extracts those two
crates." Re-measured at the start of this phase, with the brace-matching
scanner:

| edge | production sites |
|---|---|
| `core.rs` → kernel modules | 8 functions, 12 call sites |
| kernel modules → `core::Core` | 13 files |
| `get_module::<T>()` inside the kernel tier | 93 |
| distinct `core.<member>` accessors the kernel uses | 38 |

**It is only a cycle if you insist `Core` sits above the modules.** It does
not: `Core` is the substrate the six kernel modules are built on. So
`bv-kernel` went *above* `bv-core`, the 93 lookups and 38 accessors were left
exactly as they were — not one of them changed — and only the 8 downward edges
needed inverting. That reading is what turned a feared rewrite into a
tractable phase.

#### The eight inversions

Five of the eight already took `&dyn VaultCtx`; the rest needed contracts.
[`kernel_api::pipeline`](../crates/bv-kernel-api/src/pipeline.rs) is the new
file, with four traits and one hook, plus two methods added to `TokenService`:

| what `Core` called by name | now |
|---|---|
| `namespace::router::rewrite_request_for_namespace` | `RequestPipeline::rewrite_request` |
| `namespace::token_binding::enforce_request_token_binding` | `RequestPipeline::enforce_token_binding` |
| `namespace::quota::enforce_request_rate` | `RequestPipeline::enforce_request_rate` |
| `namespace::quota::enforce_write_storage_quota` | `RequestPipeline::enforce_write_storage_quota` |
| `system::denial_audit_store::record_denial` | `DenialAudit::record_denial` |
| `namespace::{store::NamespaceStore::new, migrate::resolve_root_activation}` | `RerootActivation::resolve` |
| `identity::ns_scope_migrate::run_if_needed` | `NsScopeDatafix::run_if_needed` |
| `AuthModule::token_store…root_token()` | `TokenService::mint_root_token` |
| `AuthModule::set_auth_handlers` | `TokenService::set_auth_handlers` |

None of the underlying functions changed. Each provider is a module that
already holds an `Arc<Core>`, so the traits carry operations and no context
argument — the same shape `PolicyGate` and its Phase 2 siblings take, for the
same reason.

**`RerootActivation` is the one that is not like the others**, and the reason
is ordering rather than design. It runs at the very top of `post_unseal`,
*before* `ModuleManager::setup` and deliberately before any system view or
root mount table exists, so the root tenant's first read lands at the active
prefix. At that moment no module is registered and none could have published
itself, so it takes a `&dyn VaultCtx` and the **assembly layer** registers it —
next to the plugin host, which is there for exactly the same reason.

`NsScopeDatafix` returns `Option<String>` rather than the identity module's own
`NsScopeReport`: `bv-kernel-api` cannot name a type from the kernel it is the
contract for, so what crosses is owned data. `None` is the marker-already-set
arm the caller used to read off `report.skipped`.

#### Three more edges pointed the wrong way, and two were things in the wrong place

- **`Core` held an `exchange::PreviewStore` field.** An in-memory, per-process,
  TTL-bounded cache for the `/sys/exchange/import/preview` → `/apply` flow,
  read by the HTTP surface and the Tauri host and nothing else. It is actix
  app data in `bv-server` and a field on `AppState` in the GUI now. Behaviour
  is unchanged because it was always per-process — a preview minted on one node
  was never redeemable on another.
- **`Core::post_unseal` started the scheduled-export loop by name.** The
  engines' schedulers stopped being called that way in Phase 2
  (`Module::start_background`); the export runner is not a `Module`, so it gets
  `UnsealHook`, registered by the assembly layer. It captures a **`Weak<Core>`**,
  not an `Arc`: the registry lives *on* `Core`, so an owning handle would be a
  cycle that leaks the whole vault — which matters for the desktop host, where
  cores are built and torn down in-process.
- **`logging.rs` had zero code dependencies on anything** and travelled into
  `bv-core` unchanged; `Core` needs `default_audit_options` when it bootstraps
  the audit device.

#### What each crate is

| crate | lines | contents |
|---|---|---|
| `bv-core` | 6,424 | `core.rs`, `mount.rs`, `module_manager.rs`, `kernel_impl.rs`, `seal/`, `hsm/`, `config.rs`, `logging.rs`, `server_info.rs` |
| `bv-kernel` | 32,017 | `modules/{auth,identity,policy,namespace,resource_group,system,crypto}` |

`dos` and `metrics` were left behind deliberately: both were pure re-export
shims over `bv-kernel-api` and `bv-metrics`, and `bv-core` names those
directly rather than through a facade above it. `audit::sys_emit` likewise —
its only callers are the plugin runtime, the export runner and `bv-server`,
all above.

**One crate and not six** for the kernel tier, as the target graph always
said: 93 `get_module` lookups run between those six modules, and they change
together. Splitting them would buy six more trait boundaries across a graph
with no natural cut.

**Measured outcome:**

| | before Phase 4.5 | after |
|---|---|---|
| `src/` | 65,703 lines | **27,921** — of which **12,095 are relocated tests** |
| workspace members | 44 | **46** |
| unused direct deps (`make deps-unused`) | 0 | **0** (14 more left the root with the kernel) |
| unit / integration / doctests | 1289 / 1358 / 17 | **unchanged** |
| unit test binaries | 41 | **43** |

Fourteen dependencies followed the code out: `bcrypt`, `crossbeam-channel`,
`humantime`, `lazy_static`, `priority-queue`, `radix_trie`, `stretto`,
`strum`, `strum_macros` (kernel tier) and `aes-gcm`, `hkdf`, `yubihsm`,
`rusb`, plus `hcl-rs` (seal, HSM and config, into `bv-core`).

#### `TypeId` does not survive a dev-dependency cycle

Phase 4 established that a dev-dependency cycle lets tests stay where they are:
`bastion_vault` dev-depends on `bv-server` to get `TestHttpServer` back. The
same trick was tried here for ~5,000 lines of kernel tests, and **it compiled
and then failed 25 tests at runtime.**

The reason is worth keeping. A crate's `cfg(test)` build is a *separate
compilation* from the rlib its dependents link. So `bv-kernel`'s test binary
contains two copies of `bv-kernel`: the one under test, and the one inside
`bastion_vault`. `test_utils::new_unseal_test_bastion_vault` builds a vault
through `bastion_vault::default_modules()` — the second copy — and the test
then asks for its modules by type. `get_module::<T>()` resolves by `TypeId`,
the two copies disagree, every lookup returns `None`, and the failure surfaces
as `namespace store must be installed after unseal`.

Phase 4's use of the cycle is safe because nothing crosses it by type
identity — `TestHttpServer` is used as a value, not looked up. **The rule: a
dev-dependency cycle is fine for fixtures, and unsound for anything resolved
by `TypeId`, `Any::downcast` or a type-keyed registry.**

So the 25 affected tests moved into `bastion_vault::engine_tests` after all,
where they compile once against the same rlib the vault is built from — the
fifth instance of "tests that could not travel", and the first caused by type
identity rather than a missing dependency. The other 203 `bv-kernel` tests
stayed put. Lifting them cost the Phase 3 tax again (a `use super::*` glob
stops seeing the parent's private imports), plus four private items made `pub`
with a comment saying why, and one `#[cfg(test)]` fixture regated to
`#[cfg(any(test, feature = "test-support"))]` because `test` does not cross a
crate boundary.

#### A latent Phase 4 bug this phase surfaced

`cargo check -p bv-server` failed on `log::set_boxed_logger` not existing.
Phase 4 had removed `env_logger` from the root manifest with the CLI, and
`env_logger` was what pulled in `log/std` — but a workspace-wide `cargo check`
unified the feature back in from `bvault-cli`, so the workspace stayed green
while any *downstream* consumer of `bv-server` would have failed. The root
manifest declares `log = { features = ["std"] }` now.

**The lesson for Phase 5:** `cargo check --workspace` is not a proxy for "each
crate builds". Feature unification makes it strictly weaker, and the
path-filtered per-crate matrix Phase 5 is about would have caught this.

#### The HSM feature flags, nearly no-ops for the second time

Phase 3 found four feature flags declared `= []` in the root manifest while
the `cfg` gates they drive had travelled into engine crates — so
`--features ssh_pqc` silently built without it. Moving `src/hsm` into
`bv-core` sets up exactly that trap for `hsm_mock` and `hsm_yubihsm2`, which
are seal-path features an operator turns on for real hardware. They forward
(`bastion_vault` → `bv-core`, and `bvault-cli` → `bastion_vault`, since
`bvault` is the binary an operator actually builds), and the optional
`yubihsm` / `rusb` deps moved with them. Verified by building with the
feature on, not by reading the manifest.

> **Correction (2026-08-18).** That last sentence did not hold for
> `hsm_yubihsm2`. The forwarding was right and the `yubihsm` / `rusb` deps did
> move — but `x509-cert`, which `hsm/yubihsm2.rs` uses to parse the attestation
> certificate, did **not**, so the crate named a dependency its own manifest
> did not declare and `--features hsm_yubihsm2` failed at `E0433`. Nothing
> caught it, because "verified by building with the feature on" was a one-off
> by hand and no target in the repository repeats it: the backends are off in
> every default build and AGENTS.md §5 bans `--all-features`, so the CI gate,
> `check-isolated`, `make test` and every matrix in Phase 5's table are
> default-features builds that compile *around* this code. The first build to
> notice was the container image (`BVAULT_FEATURES="hsm_mock,hsm_yubihsm2"`),
> minutes into a cross-compile — the same failure mode, and the same discovery
> channel, as the `--bin bvault` package-selection bug in 0.41.1.
>
> The fix is that the one-off is now a target: `make check-hsm` (the `hsm` job
> below). It also asserts the forwarding this section describes, from
> `cargo metadata` rather than by reading manifests — a leaf feature like
> `hsm_mock` gates no dependency, so `cargo tree` cannot see the chain at all.

### Phase 5 — CI shape — **done**

The plan, kept as written, because three of its five bullets did not survive:

> - Path-filtered jobs (`dorny/paths-filter`) → matrix of
>   `cargo nextest run -p <crate>` for affected crates only.
> - **Re-enable `tests/`**, per crate, now that each links a small crate
>   rather than the monolith. Same for the hiqlite suites, which stay on
>   `cargo test` for their process-global port allocator (see
>   `.config/nextest.toml`) but now only rebuild when `bv-storage` changes.
> - Per-crate `Swatinem/rust-cache` keys, plus `sccache` with a shared
>   bucket for the invariant substrate.
> - Keep one `cargo check --workspace` gate job so a green matrix can never
>   hide a broken assembly.
> - Update `.config/nextest.toml` and the `NOTE ON SCOPE` comment block in
>   `tests.yml` as exclusions are retired — that comment is currently the
>   honest record of what CI does not cover, and it must stay honest.

#### What CI runs now

Everything this repository has except `tests/e2e/rustion-ssh`, which needs real
remote hosts and cannot be hermetic. A push to `main` runs the lot; a pull
request runs only what the change can reach.

| job | what | when |
|---|---|---|
| `plan` | derives the affected set from `cargo metadata` | always |
| `check` | `cargo check --workspace --all-targets` | always |
| `unit` | `nextest -p <pkg> --lib` + `cargo test --doc -p <pkg>`, one job per affected package | affected ≤ 12 packages |
| `unit-full` | the same over `--workspace` | affected > 12, or `main` |
| `integration` | the ~30 `tests/` harnesses, sharded 4 ways | root crate affected |
| `hiqlite` | `make test-hiqlite` | `bv-storage` affected |
| `cucumber` | `make test-cucumber` | root crate affected |
| `isolation` | `make check-isolated` — `cargo check -p X` over every member | any manifest changed |
| `hsm` | `make check-hsm` — the seal backends, which no other job compiles | `bv-core` affected, any manifest changed, or the Containerfile moved |
| `gui` | `tsc --noEmit` + vitest | `gui/` changed |
| `deps` | `cargo machete`, advisory | always |
| `required` | one status for branch protection | always |

**Outcome #1 of this roadmap is met.** The `tests/` binaries have been skipped
in CI since the suite existed; they run now. So do the hiqlite and cucumber
suites, which were the other two documented holes.

#### `dorny/paths-filter` was the wrong instrument

Path globs are a **second copy of the dependency graph, maintained by hand**.
This document has already measured its own graph wrong three separate times,
with three different broken regexes, each time changing the plan — and a glob
list has a worse failure mode than any of those did: it drifts silently the
first time a crate gains a dependency, and the symptom is a green pull request
that skipped the suite which would have caught the bug.

So the affected set comes from `cargo metadata`, through
[`scripts/test-changed.sh --json`](../scripts/test-changed.sh) — the same code
path `make test-changed` already used locally. There is one graph, and CI and
the inner loop read it the same way. `scripts/ci-plan.sh` is the only new logic:
it turns that plan into GitHub Actions matrix outputs and decides which suites
are worth running.

`make ci-plan` runs the whole thing locally and builds nothing, so "what will CI
do with this?" is answerable before pushing:

```
make ci-plan BASE=main          # this branch
make ci-plan PKG=bv-engine-pki  # a hypothetical change to one crate
make ci-plan FULL=1             # what main runs
```

**The matrix has a cap, and the measurement is why.** Reverse-dependency closure
sizes on this tree fall into groups with a wide gap between them: 0–1 for the
Tier 4 leaves, **4–10** for every engine, auth backend, `bv-core`, `bv-kernel`,
`bv-server` and the root crate, and **26–33** for Tier 0/1. Above the cap
(12) the matrix stops being an optimisation — N jobs rebuild the same substrate
N times from the same cache — so a substrate change collapses into one
`--workspace` job. Any cap between 11 and 25 partitions those groups
identically; 12 is far enough from both edges to survive a few more crates.
`scripts/ci-plan.sh` carries the one-liner that re-derives the table, so the
number can be checked rather than trusted.

#### Per-crate cache keys would have been actively harmful

GitHub evicts caches LRU past **10 GB per repository**, and a dependency cache
for a 1200-crate debug graph is on the order of GBs. Per-crate keys — 33 of them
for a substrate change — would thrash the whole repo's budget inside one run.

What landed is two keys with **one writer each**, which took one non-obvious
correction to get right: `cargo check` emits `.rmeta` and `cargo build` emits
`.rlib`, under different metadata hashes, and they share nothing in either
direction. A single key would have meant whichever job wrote it left the other
half of CI with a useless cache — and the jobs would still pass, just slowly, so
nothing would have gone red. So `check` (written by the gate) serves the two
check-only jobs, and `build` (written by `unit-full`, which on main compiles
every dependency *and* dev-dependency for real) serves every test job. Saving
only on `main` means a pull request never pollutes the cache and always starts
from the last known-good full build.

**sccache is not adopted, and the reason is that it has no bucket.** The plan
said "sccache with a shared bucket for the invariant substrate"; the only
backend available without new infrastructure is the GitHub Actions cache, which
is the same 10 GB pool `rust-cache` is already using — so it would compete with
the thing it was meant to accelerate. Revisit when there is real object storage
to point it at. That is an infrastructure decision, not a workflow one.

#### Sharding `tests/` by binary, not by `nextest --partition`

`--partition` splits test *execution* and still builds and links every harness
in every shard. Linking is the cost that made this suite unaffordable — each
`tests/` binary was measured at **~190 MB** on this tree — so partitioning would
have multiplied the expensive half by the shard count. Shards are therefore
lists of `--test <name>` flags, assigned round-robin from the target list by
`ci-plan.sh`, so a new `tests/test_foo.rs` lands in a shard with no edit
anywhere. Eight binaries per shard is ~1.5 GB of linked output, which leaves
room on a runner's ~14 GB.

`hiqlite` is gated on `bv-storage`, as the plan said. Worth recording why that
is not the obvious gate: `tests/hiqlite_ha_fault_injection.rs` lives in `tests/`
and is therefore owned by the **root** crate, which nearly every change reaches
— gating on the owner would stand hiqlite clusters up on every pull request.
Both suites exercise `bv-storage`'s backend, so that is the trigger that means
something, and `main` runs them unconditionally.

#### The Phase 4.5 lesson is now a job

Phase 4.5 ended: "`cargo check --workspace` is not a proxy for 'each crate
builds'. Feature unification makes it strictly weaker, and the path-filtered
per-crate matrix Phase 5 is about would have caught this." It does, twice over:

- the per-package `unit` matrix builds each crate's subgraph on its own, so on a
  pull request the affected crates are checked in isolation as a side effect;
- `make check-isolated` (the `isolation` job) walks **every** member with
  `cargo check -p <pkg>`, and runs whenever any manifest changes — which is when
  feature unification can shift. One job, one target dir, sequential, so each
  check reuses what the previous one built and the only real cost is the crates
  whose feature set genuinely differs. That is exactly the set it is looking
  for.

`make check-isolated` is also the local form of the same gate, and is the answer
to "will this crate still build for a downstream consumer?"

#### What is not in this phase

- **`cargo fmt --check` is not a gate**, and that is deliberate rather than an
  omission. `rustfmt.toml` sets six nightly-only options (`imports_granularity`,
  `group_imports`, `format_strings`, `comment_width`, `binop_separator`,
  `trailing_comma`), which stable rustfmt warns about and then ignores — so
  `cargo fmt --all --check` on the stable toolchain this workflow pins reports
  diffs against a format the repo does not use. Verified, not assumed: it
  reports diffs on the current tree. A fmt gate needs a nightly rustfmt first,
  and that is its own change.
- **Timing.** No wall-clock number is claimed for this phase, because none has
  been measured — see the next section.

#### What was verified, and what was not

Stated plainly because the distinction matters more here than usual: this phase
changes the thing that verifies everything else.

**Verified locally:**

- `scripts/ci-plan.sh` against the real graph, for the working tree, for
  `--full`, for a one-engine seed (5 packages, 4 integration shards, hiqlite
  skipped) and for a substrate seed (`bv-errors` → collapse to one job, hiqlite
  run). The `.github/**` escape hatch was verified by the fact that this change
  itself forces a full plan.
- Both YAML files parse, and the `required` gate's aggregation script was run
  against both a passing and a failing `needs` payload.
- **`make check-isolated` is green: all 41 members build on their own**, in
  **~37 minutes** on a warm 10-core local tree. Most crates check in under 30s;
  the two that dominate are `bv-server` (1m22s) and `bvault-cli` (1m00s), both
  of which pull the facade and the kernel behind them. The run is also a
  demonstration of the thing it exists to catch: several crates re-checked
  `bv-errors` and its `rustls`/`ureq`/`bcrypt` chain because they need a
  narrower feature set than the workspace build unifies to. That churn is the
  cost of the check and it is the signal, not noise.
- That the tree is *not* `cargo fmt --check`-clean on stable, which is why that
  gate is absent.

**Not verified:** the workflow has never run on GitHub Actions. Job graph,
matrix expansion, cache behaviour, runner disk headroom for the integration
shards and the wall-clock cost of each job are all *reasoned*, from measured
local numbers, and the first run on `main` is what turns them into facts. The
`timeout-minutes` values are sized from the local measurements above with room
for a slower runner (`check` 120, `unit-full` 120, `isolation` 150, integration
shards 90); the integration shards are the likeliest to need revising, because
their cost is linking rather than compiling and nothing local measures that on
a 4-core box. Expect one corrective commit; that is the normal cost of a CI
change and it is cheaper than the alternative, which is not shipping the
coverage.

### Phase 6 — Independent versioning and publishing — **done**

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

#### What landed — per-crate versions, and releasing only what changed

The scheme is two versions, not one, and keeping them apart is the whole
design:

| | what | who moves it |
|---|---|---|
| **Product** | one number — `bvault --version`, the installer filenames. Root crate, `bvault-cli`, GUI. Not published. | `make bump-*` |
| **Library** | **38** independent numbers, one per publishable crate. Moved by *content*, not by release. | `make crates-bump` |

`bv-shamir` has not changed since Phase 1 extracted it. It must not be
republished because the GUI shipped, and now it is not.

The release loop:

```
make crates-plan               # what changed since its last published version
make crates-bump               # patch-bump exactly those (MINOR=<crate> if breaking)
make crates-publish-changed    # build + upload exactly those, in dependency order
make crates-tag-push           # push the release record
```

[`scripts/crates-plan.sh`](../scripts/crates-plan.sh) answers "what needs
publishing?" per crate from three inputs: the crate's last `<name>-v<version>`
git tag, `git diff <that tag> HEAD -- <crate dir>`, and the registry's sparse
index. Each crate lands in **publish**, **bump** (changed, but this version is
already on the registry) or **skip**, and the publish step refuses to run while
anything is in `bump` — a published version cannot be overwritten, so failing
early beats failing halfway through an ordered run.

#### The property everything else protects: a patch bump does not cascade

Internal deps are declared `version = "0.1.0"` — a **caret** requirement
matching every 0.1.x. So bumping `bv-errors` to 0.1.1 leaves all 32 dependents'
manifests untouched, their tarballs unchanged, and them unpublished; a consumer
resolves 0.1.1 by itself. A breaking bump (0.1 → 0.2) invalidates the
requirement, `crates-bump` rewrites all 29 dependents, and they cascade — which
is correct, because a breaking change in a dependency *is* a change in its
dependents.

Three things would destroy that property, and all three are now written down in
AGENTS.md § Per-crate versioning: pinning internal deps with `=`, letting
`make bump-*` touch library versions, and `[workspace.dependencies]` — see
below.

#### `[workspace.dependencies]` was a Phase 6 item and is now a documented "no"

It is incompatible with the thing this phase is for. Cargo **inlines** the
concrete version when it packages, so a crate using
`serde = { workspace = true }` publishes a manifest saying `serde = "1.0.228"`.
Bumping `serde` at the workspace level therefore changes the *published
manifest* of all 35 crates that use it while changing **no file in any crate
directory** — invisible to a `git diff`-based change detector, so 35 crates go
stale on the registry silently. Making it visible means treating the root
manifest as part of every crate's change signature, i.e. one `serde` bump
republishes all 38: exactly the whole-workspace release the scheme exists to
avoid.

The cost of declining it is real and is recorded rather than hidden: **83
external dependencies are declared in more than one manifest**, so version skew
between crates is possible. `Cargo.lock` unifies them for anything built from
this workspace; the exposure is a consumer resolving two of our crates from the
registry. If that bites, the answer is a lint comparing declarations across
manifests, not a shared table.

#### Two things the derivation found that a list had already lost

- **The hand-maintained publish order had drifted.** `bv-core` and `bv-kernel`
  were created in Phase 4.5 carrying `publish = ["uox-bastionvault"]` and were
  never added to `scripts/publish-crates.sh`'s `CRATES` array, so every release
  would have silently skipped the entire kernel. Order and publishability are
  now derived from `cargo metadata` — the same argument Phase 5 made against
  path-glob CI filters, and the second time in two phases that a hand-copied
  view of the graph was found stale.
- **The root crate had no `publish` key**, which means "any registry", i.e.
  crates.io. A bare `cargo publish` in the repo root would have tried to push
  the whole server there — while `docs/publishing-crates.md` said the
  accidental-publish guard was universal. It is `publish = false` now, and
  `crates-plan` warns about any manifest missing the key.

Two derivation rules that are not obvious and are load-bearing:

- **Publishability is a fixpoint, not a flag.** A crate cannot ship while
  anything it depends on cannot, so `bv-server` and `bvault-cli` drop out on
  their own from `bastion_vault` being unpublishable — and rejoin on their own
  the day it is not.
- **Path-only dev-dependencies do not count.** Cargo strips them from the
  published manifest. Without that rule `bv-kernel` would look unpublishable:
  it dev-depends on `bastion_vault` and `bv-server` for its test fixtures.

#### Verified, and not

**Verified locally:** the derived order is a valid topological sort of the
workspace graph (checked programmatically against `cargo metadata`, including
the dev-dep rule); 38 publishable crates with `bv-server`/`bvault-cli`
correctly excluded and their blockers named; a real patch bump writes only the
`[package]` version line and nothing else; a breaking bump rewrites exactly the
29 dependents; `--changed` publishes nothing when nothing changed, refuses when
a crate needs a bump first, and narrows to the right subset in topological
order when two crates are ready; the registry index is reachable and reports
the registry as empty.

**Not verified:** nothing has been published. The registry is virgin — the
index returns 404 for every crate — so the first `--execute` is also the first
test of the upload path, the inter-crate index delay, and the tagging. Do that
run by hand, not from CI: it creates 38 versions that can never be reused.

Remaining Phase 6 work:

- ~~Move shared dependency versions to `[workspace.dependencies]`.~~
  **Declined**, with reasons, above.
- ~~Resolve the root crate's unpublishability — it path-depends on the
  vendored, unpublished `ferro-*` crates in
  `third_party/ferrogate-sdk-rust/`.~~ **Done 2026-08-14.** FerroGate
  publishes the three verifier crates to its own public Cloudsmith
  registry (`uox/ferrogate`), so they are now `version` + `registry`
  dependencies pinned exactly at `=0.21.5` and the vendored tree is
  deleted. The remaining question for the facade is the
  `[patch.crates-io]` forks, not the `ferro-*` crates. See
  [docs/publishing-crates.md](../docs/publishing-crates.md)
  § Known constraints.
- ~~Rework `make bump-*`~~ **Done.** It moves the product version only —
  root `Cargo.toml`, `bvault-cli`, `gui/package.json`,
  `tauri.conf.json` — and its comment block now says why adding a
  `crates/bv-<library>` line to `_bump-write` would re-couple the two
  schemes. `bv-server` keeps its own inert `0.1.0`; it is Tier 4 but
  nothing prints it.
- **Cut the first release by hand.** The registry is empty, so the first
  `--execute` creates 38 versions that can never be reused. Do it from a
  terminal, watch the inter-crate index delay, and push the tags — then
  wire CI.
- Wire tag-triggered publishing into CI, once there has been one manual
  release to model it on. `--changed --execute` is the invocation;
  `fetch-depth: 0` is the trap, because without the tags every crate
  reads as "never released".
- **`release-plz` / `cargo-release` are not needed for this and should
  not be adopted reflexively.** What they add over what landed is
  conventional-commit parsing to *guess* the bump level — and that guess
  is the one judgement this scheme deliberately leaves to a person,
  because "is this breaking?" is a question about the crate's public API
  and a wrong answer is a broken downstream build rather than a failing
  test. Revisit only if commit discipline becomes strict enough that the
  guess is better than the default.
- `CHANGELOG.md` stays the product changelog. Per-crate changelogs only
  for crates that are actually published — i.e. not before the first
  release, and only for crates that acquire external consumers.

## Ordering rationale

Phase 1 is safe and unlocks Phase 2. Phase 2 has the design risk and
zero visible payoff — resist reordering it after Phase 3, because
extracting an engine while the cycle exists means re-doing it. Phase 3 is
where the numbers move. Phases 5 and 6 read as policy rather than engineering,
and were sequenced last on that basis — which was right for Phase 5 and only
half right for Phase 6: deriving the publishable set from the graph turned up
two live defects (a drifted publish order that omitted the whole kernel, and a
root crate that would have published itself to crates.io).

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

Done: Phases 0, 1, 2, 3, 4, 4.5, 5 and 6. The roadmap is complete; the
first manual release to `uox-bastionvault` is the remaining operational step.
