# Verification of the ACL decision core

What BastionVault proves about its authorization decisions, how, within which
bounds, and — as important — what it does **not** prove. Phases 3 and 4 of
[the formal-verification roadmap](../roadmaps/formal-verification-and-type-driven-security.md)
(T31): the proofs, and how they run continuously (§ Continuous verification).
An overclaimed guarantee is worse than none, so every claim below is scoped.

## What runs in production

Every ACL verdict — `ACL::allow_operation` and `Permissions::check` in
`crates/bv-kernel/src/modules/policy/` — is computed by
[`bv-policy-core`](../crates/bv-policy-core), a `no_std`, `unsafe`-free crate
with no dependencies whose decision code is allocation-free (only the
share-name conversions `ShareCap::from_names` / `to_names` allocate, and no
decision calls them). The kernel keeps only the *index*:
the radix tries and the segment-wildcard map that find the candidate rules for
a path, and the code that answers the core's questions about a request
(`core_bridge.rs`). Removing the crate breaks the kernel build.

So the proofs below are statements about the code that decides production
requests, not about a model of it.

## What is proved

Kani model-checks the core over **every** answer the index could give within
the bounds: every combination of candidate lookups, layer rules (path match,
gate verdict, filter, capability bitmap, wrapping TTLs, parameter facts) and
queries. The harnesses are in `crates/bv-policy-core/src/proofs.rs`.

| # | Theorem | Harness(es) | Holds for |
|---|---|---|---|
| T1 | **Deny supremacy.** A deny that governs the path, or a gated/scoped deny rule that applies, yields exactly `deny`: not allowed, no other capability, no LIST filter, no granting policy — whatever gated or scoped grant competes with it. On enforcement it also yields no `root_privs`. | `t1_deny_wins_in_capability_probes`, `t1_deny_wins_on_enforcement` | Capability probes (`check_only`: `sys/capabilities`, the policy dry-run, `capabilities()`) and enforcement (`pre_route`, `readable_targets`). A probe keeps a `root_privs` it had already reported before a layered deny applied. Until T119 the enforcement half was refuted (F6, below). |
| | A governing deny with no layered rule applying grants nothing, and deny is absorbing when two rules for the same path merge. | `t1_a_governing_deny_grants_nothing`, `t3_merge_keeps_deny_and_never_drops_a_capability` | Enforcement and probes. |
| T2 | **Fail-closed.** No governing ungated rule and no layered rule that applies ⇒ not allowed, no capability, no `root_privs`, no filter, no granting policy. | `t2_no_rule_means_no_grant` | Everything except `help` (always allowed) and the root ACL. |
| T3 | **Grant monotonicity.** Merging two same-path rules is a bitwise union unless one denies. Adding a non-deny gated or scoped rule never revokes `allowed`, `root_privs` or a capability bit. | `t3_merge_keeps_deny_and_never_drops_a_capability`, `t3_an_added_layered_grant_never_removes_a_capability` | Capability bits. Parameter constraints are *not* monotone under merge (a merged `required_parameters` / `allowed_parameters` can refuse what one rule alone allowed) — Vault-compatible, not a guarantee. |
| T4 | **Specificity precedence and determinism.** The exact rule governs whenever one exists; for LIST the trailing-slash-trimmed exact rule is next; otherwise the most specific non-exact rule. "Most specific" is a strict total order (a later first wildcard wins; at the same position a rule without a trailing `*` wins; then fewer `+`; then longer; then the path), and the selected winner is the same in every iteration order of the segment-wildcard map. `+` matches exactly one non-empty segment; a rule without `*` matches only paths of its own length. | `t4_exact_rules_take_precedence`, `t4_specificity_is_a_strict_total_order`, `t4_the_most_specific_candidate_wins_in_any_order`, `t4_segment_wildcards_match_by_shape` | Precedence is *between* rules: a more specific grant beats a less specific deny (Vault-compatible). |
| T5 | **Group-gate soundness.** A gated rule passes iff the target is in one of its groups; a gated rule whose gate fails contributes nothing to a non-LIST request. | `t5_group_gate_is_sound`, `t5_t6_a_failed_gate_contributes_nothing` | Non-LIST requests (LIST waives the gate by design, see T5b). |
| T5b | **The LIST carve-out cannot become "return everything".** With only gated/scoped rules, a LIST granted through them always carries a filter. With ungated rules too, a LIST reported with no filter means the governing ungated rule's own check reported `list` — it granted the LIST on enforcement, or its bitmap carries `list` in a probe. A broader ungated rule that does not govern the path cannot lift the filter. | `t5b_gated_list_always_carries_a_filter`, `t5b_an_unfiltered_list_needs_the_governing_rule`, `t5b_a_non_governing_list_rule_keeps_the_filter` | Enforcement and probes. Until T120 only the weaker form held — any ungated rule the index found carrying `list` lifted the filter (F7, below). |
| T6 | **Scope-gate soundness.** `owner` passes only for the target's owner (or a write to an unowned target — first write records ownership); `shared` passes only when the caller's shares include the override capability if one is named, else the capability the operation needs; unknown scopes never pass; no caller entity, no pass. A failed scope contributes nothing to a non-LIST request. | `t6_scope_gate_is_sound`, `t5_t6_a_failed_gate_contributes_nothing` | Exact characterisation (sound and complete). |
| T7 | **Root isolation.** Only the root ACL yields `is_root`, and it is always allowed with `root_privs`. A non-root ACL yields `root_privs` only when an evaluated permission set (the governing rule, or a layered rule that applies) carries `sudo`. | `t7_root_isolation` | `root_privs` comes from `sudo`, by design — it is not exclusive to the root ACL. |
| T8 | **Parameter constraints.** On `read`/`write`: a missing `required_parameters` key refuses; a parameter matching its `denied_parameters` entry, or any parameter under a `"*"` deny key, refuses; under a restrictive `allowed_parameters` (not empty, not only `"*"`) a value that is not allowed, or an unlisted key without `"*"`, refuses. A grant also needs the capability and wrapping TTLs that are not inverted, and the characterisation is complete. | `t8_parameter_constraints` | `read` and `write` only: on every other operation the parameters are **not consulted** (proved). A request with no parameters at all skips the allow/deny lists. |
| T9 | **Probe-only capabilities.** `connect` and the eleven SQL capabilities (`CAP_PROBE_ONLY`, bits 9–20; features/sql-browser.md §3) decide nothing but their own bits: removing them from every candidate leaves `allowed`, `root_privs`, `is_root`, the LIST filter and every granting-policy and filter effect unchanged, and changes the bitmap in exactly those bits. A probe-only bit is reported only when an evaluated permission set (the governing rule, or a layered rule that applies) carries that very bit, so none implies another and no ordinary capability implies one. A deny that governs or applies leaves none. | `t9_probe_only_capabilities_decide_nothing_but_their_own_bits`, `t9_a_probe_only_capability_needs_a_rule_that_carries_it` | Enforcement and probes. T1, T2 and T6 already quantify over every `u32` bitmap and every `u16` share set, so deny supremacy, the fail-closed default and the scope gate (with the share override a SQL probe sets) hold for the new bits unchanged. |

Each harness has at least one `kani::cover` vacuity guard: an `UNSATISFIABLE`
cover means the harness's interesting case is unreachable and the harness
proves nothing, which fails the gate.

### Defect witnesses

A defect witness states no theorem; it `cover`s behaviour the evaluator is
not meant to have. `SATISFIED` means the defect is present (Kani prints the
input). When the fix lands it turns `UNSATISFIABLE` — failing the gate on
purpose — and becomes an `assert` (the text is in the harness).

No defect witness is open in the core today: F6 and F7 were witnesses and are
now theorems (below). F8 was outside the core, in the host's matcher, and was
pinned by an HCL test instead; it is fixed too (below).

**F6 — fixed (T119).** It was deny supremacy refuted on
enforcement. Its witness's covers turned `UNSATISFIABLE` with the fix and the
harness became the theorem `t1_deny_wins_on_enforcement` (T1, above), keeping
the two shapes it witnessed as covers. `f6_current_behaviour_*` became
`f6_a_*` / `f6_b_*` in `policy::differential`, which assert the fixed
verdict on HCL, and `src/engine_tests/kernel_policy_deny.rs` asserts it
through `pre_route`, `readable_targets` and `may_connect_target` with the
asset groups, owner and shares resolved from storage.

**F7 — fixed (T120).** A gated or scoped LIST filter was dropped when *any*
ungated rule the index found for the path carried `list` — including the
most specific prefix rule when an exact rule that withholds `list` governs,
and the trimmed exact rule when the untrimmed one governs — so a LIST
granted only through a `groups`/`scopes` rule was served unfiltered. Only the
governing rule decides now, through its own check. The witness's cover
turned `UNSATISFIABLE` with the fix and the harness became the theorem
`t5b_a_non_governing_list_rule_keeps_the_filter`; the weak T5b harness was
replaced by its strong form, `t5b_an_unfiltered_list_needs_the_governing_rule`.
`f7_current_behaviour_*` became `f7_a_non_governing_list_rule_keeps_the_filter`
in `policy::differential`, which asserts the filter on HCL in both modes.

**F8 — fixed (T121).** A `groups`- or `scopes`-qualified segment-wildcard
rule ending in `*` (`secret/+/data/*`) matched no real path: `Policy::init`
keeps such a rule's `*` in its path, the ungated index reads it back as a
prefix glob, and the layers compared it as a literal segment. Its grant never
applied and its `deny` was ignored. Layered rules now take their shape from
`RuleShape::of` in `acl.rs`, which reads the glob through the same function
as the ungated lookup (`segment_wildcard_glob`), and both layers match
through `RuleShape::matches`. `f8_current_behaviour_*` became five
`f8_*` tests in `policy::differential` asserting the fixed behaviour on HCL in
both modes, and `src/engine_tests/kernel_policy_segment_glob.rs` asserts it
through `pre_route`, the LIST filter, `readable_targets` and
`may_connect_target`.

There is no Kani harness for F8, on purpose. The core never sees a rule's
path: it asks the host whether layer rule *i* matches (`Layer::matches`) and
quantifies over every answer, and `segments_match` takes `is_prefix` already
decided. The defect was in the host computing those inputs from strings
(`strip_suffix('*')` over `PolicyPathRules`), which is the unproved "real
string matching in the index" below. A harness over the core could only
restate `segments_match` (T4 already proves it) or prove a model of the host;
neither says production's layers and index agree. That statement is made on
real strings by the differential property
`a_qualified_rule_matches_what_the_same_rule_matches_ungated` (below).

## Bounds

| Bound | Value | Why it is enough / what it means |
|---|---|---|
| `MAX_RULES` | 4 per layer (group-gated, scope-filtered) | Covers a deny before and after a grant, two grants, and a filter/no-filter pair in each layer, plus the three ungated candidates. Production layers are unbounded. |
| `MAX_SEGMENTS` | 4 | The matcher compares segment *i* of the rule with segment *i* of the path only; four segments give prefix rules longer paths and two `+` in one rule. |
| Path alphabet | `Empty`, `A`, `Ab`, `B`, `Plus` | Between one rule segment and one path segment this realises every combination of the four predicates the matcher observes (equal, proper prefix, unrelated, empty, `+`). The roadmap's 3-symbol sketch had no empty segment and no prefix relation, both of which production depends on (LIST paths, prefix rules). |
| Parameter keys | 3 (+ `"*"`) | T8 over every subset of present / required / denied / allowed keys and value verdicts. |
| Groups / scopes | 3 groups; up to 3 scope entries | T5 / T6 over every subset. |
| `#[kani::unwind(5)]` | every harness | Bound + 1: no loop in any harness runs more than 4 times; Kani's unwinding assertions (on by default) fail a harness whose bound is too small. |

## What is **not** proved

- **More than 4 rules in a layer, or paths longer than 4 segments.** The
  decision code has no length-dependent branches, but a bounded proof is a
  bounded proof.
- **Real string matching in the index.** Which exact / prefix rule the radix
  tries return, string normalisation (leading `/`, trailing `/` trimming),
  `str::starts_with` / `==` on real segments, the specificity *inputs*
  (`find('+')`, byte lengths), the reading of a rule's trailing `*` into a
  prefix shape (F8), case-insensitive group names, case-folded parameter keys
  and glob-matched JSON values. Mitigated, not proved, by the differential
  suite below.
- **The asynchronous inputs.** `asset_groups`, `asset_owner` and
  `target_shared_caps` are resolved in `PolicyStore::post_auth` against
  storage. The core decides correctly *given* them.
- **Everything upstream of the evaluator.** Token lookup, TTL, renewal,
  revocation, policy templating, namespace resolution of policy names, and
  whether a route reaches `pre_route` at all (Phase 1 makes that structural).
- **The `bare_mount` heuristic** behind `has_mount_access` (mount visibility,
  not authorization).
- **Callers' interpretation of the result**, e.g. `readable_targets` treating
  `root_privs` as readable (sound for a deny since T119, which clears
  `root_privs` on enforcement), or `may_connect_target` treating an ungated
  `read` as `connect`. `PolicyGate::sql_privileges` reads a SQL verdict as
  `is_root`, or the probed bit without `deny`; its synthetic path building and
  name canonicalization (`bv_kernel_api::policy::sql`) are tested, not proved.
- **Concurrency** (`DashMap` interleavings) and wrapping-TTL enforcement
  (only the inverted-TTL refusal is decided).

## The differential suite

`crates/bv-kernel/src/modules/policy/differential/` runs the production
evaluator against a frozen, verbatim copy of the evaluator as it was before it
delegated (`legacy.rs`), over generated HCL policy sets (merging, nesting,
`+`, trailing `*`, groups, scopes, parameter lists, TTLs, old-style `policy`)
and generated requests (all operations, leading/trailing `/`, `data` / `body`,
entity, owner, shares, override), in enforcement and probe mode. They must
agree on the verdict, capabilities, `root_privs`, granting-policy names, LIST
filter entries and their order, `capabilities()`, `has_mount_access`, the
scope diagnostics and the built index.

The generated rules draw one to three of the eleven SQL capabilities in three
rules out of ten (T124), and generated shares and share overrides include
`sql_select` and `sql_drop`. Parameter constraints are dropped from any rule
sharing its raw path with a SQL rule, because `Policy::init` refuses that
combination. `capability_bit_layout_matches_core` pins every `Capability` to
its `bv-policy-core` constant, including `CAP_SQL_ALL` and `CAP_PROBE_ONLY`.
T9 has no real-strings property: one that compared two ACLs built from the
same generated text, with and without the SQL capabilities, found that two
builds of identical text can disagree on `root_privs` in a capability probe
(`PolicyConfig.path` is a `HashMap`, so rule order varies per parse). That
disagreement does not involve the SQL capabilities and is open.

`a_qualified_rule_matches_what_the_same_rule_matches_ungated` (T121) checks
the host against itself rather than against `legacy`: for every generated
rule path, the rule grants a read of a path ungated exactly when it grants
it `groups`-gated and `scopes`-filtered with the qualifier passing. It uses
reads because for LIST the ungated index also consults the trimmed exact
rule, a precedence step the layers do not take.

```bash
cargo nextest run -p bv-kernel --lib differential                         # 1024 cases, fixed seed
PROPTEST_CASES=100000 cargo nextest run -p bv-kernel --lib differential   # the Phase 3 gate
```

## Running the proofs

```bash
make bootstrap                       # installs cargo-kani and runs `cargo kani setup`
make verify-kani KANI_SET=full       # every harness, judged by the gate (below)
make verify-kani                     # the fast set (tier 1)
cargo kani -p bv-policy-core --exact --harness proofs::t1_deny_wins_in_capability_probes
```

Verified with **Kani 0.68.0 / CBMC 6.11.0**, solver CaDiCaL (Kani's default;
no harness sets `kani::solver`). The versions are pinned in
`scripts/kani-harnesses.txt`, and the gate refuses a log from any other
version: a bump is its own change, with the full set green before merge.
Results of the run that closed Phase 3.1–3.4 are in the roadmap's Phase 3
implementation record.

A bare `cargo kani` exit status is **not** the result. Kani exits 0 when a
cover is `UNSATISFIABLE`, i.e. on a vacuous proof; use the gate.

## Continuous verification

Phase 4 runs all three of the roadmap's guarantees — the `Authorized<R>` route
witness, the SQL guard, and these proofs — in tiers of rising cost. The
Makefile targets are the reference; `.github/workflows/verify.yml` runs the
same targets.

| Tier | Command | Contents | When in CI | Measured locally |
|---|---|---|---|---|
| 0 | `make verify-fast` | SQL text gate; Semgrep; `clippy -D warnings` and tests (incl. `trybuild`) of `bv-policy-core` and `bv-sql-guard`; harness inventory; the gate's self-test; route inventory + golden files + registration gate (`bv-server` `routes::`, `authz::`); the `Authorized<R>` `compile_fail` doctests | every push and PR | 33 s |
| 1 | `make verify` | tier 0 + the Kani **fast set** + the differential suite at 10 000 cases | PRs that reach `bv-policy-core` / `bv-kernel`, pushes to `main` | 146 s (Kani 92 s) |
| 2 | `make verify-full` | tier 0 + **every** harness + the differential suite at 1 000 000 cases | nightly, `workflow_dispatch` | 35 min (Kani 245 s, 1M cases 851 s, the rest a test-harness rebuild) |
| 3 | `make verification-report` | `verification-report.md` from the recorded evidence | `releases/*` tags: tier 2 in one job, the report attached to the release | seconds |

Local timings: Apple M-series, warm `target/`, Kani 0.68.0. CI timings are
not measured yet. In CI, tier 0 leaves two of its checks to `tests.yml`,
which already runs them: Semgrep (the `sql-guard` job, recorded as an
explicit `SKIPPED` step in verify.yml's tier 0) and the `bv-server` route and
doctest checks (`Unit bv-server`, whenever a change can reach it). Tier 3
runs everything itself.

Without Semgrep installed, `make verify-fast` fails and says how to install
it; `SEMGREP=0` records the step as `SKIPPED` instead. A skipped step never
counts towards a tier.

### The gate

`scripts/verify.py` judges a Kani run against `scripts/kani-harnesses.txt`,
the harness inventory (name, theorem or witness, fast or slow, cover count).
Everything below fails the gate:

| Result | Why it blocks |
|---|---|
| `VERIFICATION:- FAILED` | A real counterexample. The gate re-runs the harness with concrete playback to print the input; Kani 0.68.0 does not produce one for every failure (not for an `assert_eq!` with a runtime-formatted message), and the gate says so when it does not. |
| a check `UNDETERMINED`, or no result / no final summary | An undischarged proof is not a pass: a timeout, crash or compile error. |
| a theorem's cover not `SATISFIED` | The harness's interesting case is unreachable, so it proves nothing. |
| an assertion in the harness function `UNREACHABLE` | Same: an assertion that cannot be reached proves nothing. None is today. |
| a cover count other than the manifest's | A vacuity guard was added or removed without the inventory. |
| a harness missing from, or not listed in, the manifest | A proof cannot report its own disappearance. Also checked statically by `make verify-gates`, with every harness's explicit `#[kani::unwind]`. |
| a Kani or CBMC version other than the pin | An unpinned verifier makes a claim unreproducible. |

A **defect witness** (`f<n>_*`; none is open today) whose covers are all `SATISFIED` is a
**known open finding**: the gate passes, and prints and reports it as one.
If a witness's cover becomes `UNSATISFIABLE`, the defect no longer
reproduces and the gate fails on purpose — replace the cover with the
`assert` in the harness's doc comment and make the row a `theorem` (see
§ Defect witnesses).

`make verify-gates` runs the gate's self-test, which drives every rule above
against synthetic logs. The gate was also checked against real output: the
log of a full run passes; the same log with one theorem cover and the F7
witness cover (before T120) edited to `UNSATISFIABLE` fails with both problems named; and a mutant
core (`d.caps = CAP_DENY` → `d.caps |= CAP_DENY` in the layer wipe, the
roadmap's example; since T119 that line is in `decide.rs`'s `denied`) is
caught by `t1_deny_wins_in_capability_probes` in the fast set.

### The fast set

Every harness measured at or under 20 s is in the fast set: 14 harnesses,
76.8 s of verification time after T120 (its two T5b harnesses measured 10.5 s
and 6.2 s), including at least one harness for each of T1–T8. The four slow ones —
`t4_the_most_specific_candidate_wins_in_any_order` (81 s),
`t3_an_added_layered_grant_never_removes_a_capability` (32 s),
`t1_deny_wins_on_enforcement` (29.5 s), and
`t5_t6_a_failed_gate_contributes_nothing` (26 s) — run in tier 2 only. No
harness falls between 14.1 s and 26.3 s, so the split does not depend on the
exact threshold. Re-measure before moving a row (the `secs` column).

T124 added T9's two harnesses (full run of 2026-10-26, 20 harnesses, 326 s
wall): `t9_a_probe_only_capability_needs_a_rule_that_carries_it` (19.1 s) is
fast and `t9_probe_only_capabilities_decide_nothing_but_their_own_bits`
(29.2 s) is slow. The fast set is now 15 harnesses, 93.0 s on that run,
covering T1–T9. Its slowest harness is the T9 one, 0.9 s under the threshold,
and the fastest slow harness on that run measured 26.8 s, so a slower machine
could move T9's fast harness across: re-measure before trusting the split.

### The report

`make verification-report` writes `target/verify/verification-report.md`:
commit, tag, working-tree state, verifier versions, the tier reached, a
verdict, and per guarantee the result of each check, with the per-harness
table, the known open findings and the bounds. Every step records the exact
tree it ran on (the commit, plus a fingerprint of any uncommitted change), and
the report counts only records of the tree it describes: a step with no
record is `NOT RUN`, a record from another tree is `STALE`, and neither is
read as a pass. `REQUIRE_TIER=2` makes an incomplete report an error; a
`releases/x.y.z` tag that does not match `Cargo.toml` is a `FAIL`.
