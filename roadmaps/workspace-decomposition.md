# Roadmap: Workspace Decomposition

Status: **Phases 0, 1 and 2 are done.** Phase 3 is next and its extraction
order is free.

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

### Phase 3 — Engines out, starting with PKI

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

Done so far: Phases 0, 1 and 2. Phase 3 is next.
