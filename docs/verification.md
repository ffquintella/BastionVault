# Verification of the ACL decision core

What BastionVault proves about its authorization decisions, how, within which
bounds, and — as important — what it does **not** prove. Phases 3 and 4 of
[the formal-verification roadmap](../roadmaps/formal-verification-and-type-driven-security.md)
(T31): the proofs, and how they run continuously (§ Continuous verification).
An overclaimed guarantee is worse than none, so every claim below is scoped.

## What runs in production

Every ACL verdict — `ACL::allow_operation` and `Permissions::check` in
`crates/bv-kernel/src/modules/policy/` — is computed by
[`bv-policy-core`](../crates/bv-policy-core), a `no_std`, allocation-free,
`unsafe`-free crate with no dependencies. The kernel keeps only the *index*:
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
| T1 | **Deny supremacy.** A deny that governs the path, or a gated/scoped deny rule that applies, yields exactly `deny`: not allowed, no other capability, no LIST filter, no granting policy. | `t1_deny_wins_in_capability_probes` | Capability probes (`check_only`: `sys/capabilities`, the policy dry-run, `capabilities()`). |
| | A governing deny with no layered rule applying grants nothing, and deny is absorbing when two rules for the same path merge. | `t1_a_governing_deny_grants_nothing`, `t3_merge_keeps_deny_and_never_drops_a_capability` | Enforcement and probes. |
| | **Not** for enforcement with layered rules — see F6 below. | `f6_enforcement_lets_a_layered_grant_override_deny` (defect witness) | — |
| T2 | **Fail-closed.** No governing ungated rule and no layered rule that applies ⇒ not allowed, no capability, no `root_privs`, no filter, no granting policy. | `t2_no_rule_means_no_grant` | Everything except `help` (always allowed) and the root ACL. |
| T3 | **Grant monotonicity.** Merging two same-path rules is a bitwise union unless one denies. Adding a non-deny gated or scoped rule never revokes `allowed`, `root_privs` or a capability bit. | `t3_merge_keeps_deny_and_never_drops_a_capability`, `t3_an_added_layered_grant_never_removes_a_capability` | Capability bits. Parameter constraints are *not* monotone under merge (a merged `required_parameters` / `allowed_parameters` can refuse what one rule alone allowed) — Vault-compatible, not a guarantee. |
| T4 | **Specificity precedence and determinism.** The exact rule governs whenever one exists; for LIST the trailing-slash-trimmed exact rule is next; otherwise the most specific non-exact rule. "Most specific" is a strict total order (a later first wildcard wins; at the same position a rule without a trailing `*` wins; then fewer `+`; then longer; then the path), and the selected winner is the same in every iteration order of the segment-wildcard map. `+` matches exactly one non-empty segment; a rule without `*` matches only paths of its own length. | `t4_exact_rules_take_precedence`, `t4_specificity_is_a_strict_total_order`, `t4_the_most_specific_candidate_wins_in_any_order`, `t4_segment_wildcards_match_by_shape` | Precedence is *between* rules: a more specific grant beats a less specific deny (Vault-compatible). |
| T5 | **Group-gate soundness.** A gated rule passes iff the target is in one of its groups; a gated rule whose gate fails contributes nothing to a non-LIST request. | `t5_group_gate_is_sound`, `t5_t6_a_failed_gate_contributes_nothing` | Non-LIST requests (LIST waives the gate by design, see T5b). |
| T5b | **The LIST carve-out cannot become "return everything".** With only gated/scoped rules, a LIST granted through them always carries a filter. With ungated rules too, an unfiltered LIST means the governing rule granted it or some ungated rule the index finds for the path carries `list`. | `t5b_gated_list_always_carries_a_filter`, `t5b_an_unfiltered_list_needs_an_ungated_list_grant` | **Not** "the governing ungated rule" — see F7 below. |
| T6 | **Scope-gate soundness.** `owner` passes only for the target's owner (or a write to an unowned target — first write records ownership); `shared` passes only when the caller's shares include the override capability if one is named, else the capability the operation needs; unknown scopes never pass; no caller entity, no pass. A failed scope contributes nothing to a non-LIST request. | `t6_scope_gate_is_sound`, `t5_t6_a_failed_gate_contributes_nothing` | Exact characterisation (sound and complete). |
| T7 | **Root isolation.** Only the root ACL yields `is_root`, and it is always allowed with `root_privs`. A non-root ACL yields `root_privs` only when an evaluated permission set (the governing rule, or a layered rule that applies) carries `sudo`. | `t7_root_isolation` | `root_privs` comes from `sudo`, by design — it is not exclusive to the root ACL. |
| T8 | **Parameter constraints.** On `read`/`write`: a missing `required_parameters` key refuses; a parameter matching its `denied_parameters` entry, or any parameter under a `"*"` deny key, refuses; under a restrictive `allowed_parameters` (not empty, not only `"*"`) a value that is not allowed, or an unlisted key without `"*"`, refuses. A grant also needs the capability and wrapping TTLs that are not inverted, and the characterisation is complete. | `t8_parameter_constraints` | `read` and `write` only: on every other operation the parameters are **not consulted** (proved). A request with no parameters at all skips the allow/deny lists. |

Each harness has at least one `kani::cover` vacuity guard: an `UNSATISFIABLE`
cover means the harness's interesting case is unreachable and the harness
proves nothing, which fails the gate.

### Defect witnesses

Two harnesses state no theorem; they `cover` behaviour the evaluator is not
meant to have. `SATISFIED` means the defect is present (Kani
prints the input). When the fix lands they turn `UNSATISFIABLE` — failing the
gate on purpose — and become `assert`s (the text is in each harness).

| | Defect | Witness | Reproduced on real HCL |
|---|---|---|---|
| F6 | Authorization-relevant finding. Details are withheld from this repository until the fix ships; the maintainer holds the write-up. | `f6_*` | `f6_current_behaviour_*` in `bv-kernel` `policy::differential` |
| F7 | Evaluator finding. Details are withheld from this repository until the fix ships; the maintainer holds the write-up. | `f7_*` | `f7_current_behaviour_*` |

F8 (outside the core): an evaluator finding in the host's matcher, pinned by
`f8_current_behaviour_*`. Details withheld until the fix ships.

All three are preserved unchanged by Phase 3 (no behaviour change) and are
recorded, with the proposed fixes, in the roadmap's Findings.

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
  (`find('+')`, byte lengths), case-insensitive group names, case-folded
  parameter keys and glob-matched JSON values. Mitigated, not proved, by the
  differential suite below.
- **The asynchronous inputs.** `asset_groups`, `asset_owner` and
  `target_shared_caps` are resolved in `PolicyStore::post_auth` against
  storage. The core decides correctly *given* them.
- **Everything upstream of the evaluator.** Token lookup, TTL, renewal,
  revocation, policy templating, namespace resolution of policy names, and
  whether a route reaches `pre_route` at all (Phase 1 makes that structural).
- **The `bare_mount` heuristic** behind `has_mount_access` (mount visibility,
  not authorization).
- **Callers' interpretation of the result**, e.g. `readable_targets` treating
  `root_privs` as readable.
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

A **defect witness** (`f6_*`, `f7_*`) whose covers are all `SATISFIED` is a
**known open finding**: the gate passes, and prints and reports it as one.
If a witness's cover becomes `UNSATISFIABLE`, the defect no longer
reproduces and the gate fails on purpose — replace the cover with the
`assert` in the harness's doc comment and make the row a `theorem` (see
§ Defect witnesses).

`make verify-gates` runs the gate's self-test, which drives every rule above
against synthetic logs. The gate was also checked against real output: the
log of a full run passes; the same log with one theorem cover and the F7
cover edited to `UNSATISFIABLE` fails with both problems named; and a mutant
core (`d.caps = CAP_DENY` → `d.caps |= CAP_DENY` in the layer wipe, the
roadmap's example) is caught by `t1_deny_wins_in_capability_probes` in the
fast set.

### The fast set

Every harness measured at or under 20 s is in the fast set: 15 harnesses,
84 s of verification time, including both witnesses and at least one harness
for each of T1–T8. The three slow ones —
`t4_the_most_specific_candidate_wins_in_any_order` (81 s),
`t3_an_added_layered_grant_never_removes_a_capability` (32 s) and
`t5_t6_a_failed_gate_contributes_nothing` (26 s) — run in tier 2 only. No
harness falls between 14.1 s and 26.3 s, so the split does not depend on the
exact threshold. Re-measure before moving a row (the `secs` column).

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
