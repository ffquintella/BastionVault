# Roadmap: Formal Verification & Type-Driven Security

Progressive adoption of three complementary guarantees for BastionVault's highest-risk paths:

1. **Structural** — no privileged HTTP route can be served without passing the authorization chokepoint, enforced by the type system at the route-registration site rather than by developer memory.
2. **Mechanical** — no SQL statement can carry unparameterized request data or an unvalidated identifier, enforced by newtypes plus a lint gate.
3. **Mathematical** — the ACL decision function's security invariants hold for *every* input in a bounded model, proved by model checking (Kani) rather than sampled by tests.

Each phase is independently shippable and adds no runtime cost to the hot path. Nothing here changes vault behaviour on its own: phases 1–2 are refactors that make a class of mistake uncompilable, phase 3 adds a verified crate the production evaluator delegates to, phase 4 makes the checks continuous.

## Goals

- Make the v0.37.6 class of defect — a handler that does privileged work before (or instead of) crossing `TokenStore::pre_route` — a **compile error**, not a review finding.
- Reduce the SQL surface to a small set of statements that are literals-plus-validated-identifiers by construction. (The `LIKE`-pattern defect found while scoping this roadmap is already closed — see § Findings.)
- Prove the security theorems of the ACL evaluator (deny supremacy, fail-closed default, gate soundness, specificity precedence) over an exhaustive bounded input space, and keep the proved artifact and the shipped artifact the *same code*.
- Run all of it in CI within a per-PR budget of minutes, on a crate that builds even though the full workspace currently cannot resolve a lockfile.

## Status

| Phase | Title | Status |
|---|---|---|
| 0 | Baseline: route inventory + threat model sign-off | `[/]` In progress — the inventory is code (Phase 1.3: route table + golden files, no `Unknown` rows) and F2–F4 shipped; the ESI premise-change request for phases 1 and 3.4 is a human process and is **outstanding** |
| 1 | Structural API hardening (`Authorized<R>` witness + route table) | `[x]` Done — deviations in § Phase 1 → Implementation record |
| 1.1 | `SysRoute` trait + `Authorized<R>` extractor | `[x]` Done — `crates/bv-server/src/authz.rs`; compile-fail doctests (not `trybuild`, see record) |
| 1.2 | Migrate the 44 inline `sys` handlers to the witness | `[x]` Done — all 48 inline handlers in today's tree (44 at scoping time); `/metrics` and the Rustion webhook behind their own witnesses |
| 1.3 | Route table as data + anonymous-surface golden file | `[x]` Done — `crates/bv-server/src/routes.rs`, `src/sys/routes.rs`, `tests/golden/{anonymous-routes,route-inventory}.txt` |
| 2 | SQL injection elimination (`SqlIdent` / `Sql` + lint gate) | `[x]` Done (2.4 is optional and not adopted) |
| 2.1 | `bv-sql-guard` crate + `LIKE`-pattern fix | `[x]` Done — `SqlIdent` / `Sql` / `sql!` / `escape_like`, `trybuild` compile-fail cases |
| 2.2 | Migrate hiqlite + MySQL backends to the guarded API | `[x]` Done |
| 2.3 | Mechanical gate (Semgrep ruleset), escape-hatch registry | `[x]` Done — `sql-guard` CI job; Semgrep ruleset not yet run (no local Semgrep), text gate verified red/green |
| 2.4 | Optional: `dylint` AST lint replacing the text gate | `[ ]` Todo |
| 3 | Formal verification of the permission engine (Kani) | `[/]` In progress — 3.1, 3.3, 3.4 done; T119 fixed the F6 refutation, and 3.2 remains open for F7/T120 and the outstanding ESI notification. See § Phase 3 → Implementation record and § T119 |
| 3.1 | Extract `bv-policy-core` (bounded, `no_std`, pure) | `[x]` Done — `crates/bv-policy-core`, no dependencies; decision code only, the index stays in the host |
| 3.2 | Kani harnesses T1–T8 + vacuity guards | `[/]` 18 harnesses, all `SUCCESSFUL`, every cover `SATISFIED` (Kani 0.68.0). T1 now holds on enforcement too (T119 fixed F6; its witness is the theorem `t1_deny_wins_on_enforcement`). T5b holds for "some ungated rule lists" only; its stronger form is refuted on enforcement — F7 (defect witness) — so 3.2 closes with T120 |
| 3.3 | Differential equivalence vs. production `ACL` (proptest) | `[x]` Done — against a frozen copy of the pre-delegation evaluator; 100 000 cases green, no counterexample |
| 3.4 | Production delegates to the verified core | `[x]` Done — `ACL::allow_operation`, `Permissions::check`, `Permissions::merge` (capabilities), the specificity sort and the segment matcher call the core; no behaviour change |
| 4 | CI/CD orchestration + release verification report | `[/]` In progress — tiers, gate, workflow and report generator landed and were run locally (tiers 0–2 green; the report generated from real tier-1 evidence); the workflow has never run in CI, so the DoD items that need it are open. See § Phase 4 → Implementation record |
| 4.1 | Tiers 0–2 as Make targets + the Kani gate | `[x]` Done — `make verify-fast` / `verify` / `verify-full`, `scripts/verify.py`, `scripts/kani-harnesses.txt`; fast set chosen by measurement (14 of 18 harnesses after T119) |
| 4.2 | `.github/workflows/verify.yml` | `[/]` Written and planned from `scripts/ci-plan.sh`; YAML and every `run:` script syntax-checked, the plan logic dry-run per event; never executed on a runner |
| 4.3 | Tier 3: `verification-report.md` | `[/]` Generator done and run locally against real tier-1 evidence (a Kani fast-set result); not yet run on tier-2 evidence, produced by CI for a tag, or attached to a release |

## Deviations from the original brief

Recorded up front, per `agent.md`'s "explain assumptions clearly".

| Brief said | Reality in this repo | Decision |
|---|---|---|
| **SQLx** for query hardening | `sqlx` was **removed** from the project (`libsqlite3-sys` link conflict — see `ROADMAP.md`, Storage: `[~] Removed`). Persistence is hiqlite (raw SQL + `Param` binding) and Diesel/MySQL (query builder + three `sql_query` sites). | Do **not** reintroduce `sqlx`. It would resurrect a known build break and violate `agent.md`'s dependency rules for zero gain — the existing drivers already parameterize values. Phase 2 targets the two real gaps: interpolated **identifiers** and `LIKE`-pattern semantics. |
| **Axum** or Actix extractors | `actix-web 4.13` (`src/http/mod.rs`). | Actix `FromRequest` is the extractor mechanism. The witness pattern below is framework-idiomatic for both, so a future migration keeps the guarantee. |
| **MIRAI** for taint analysis | MIRAI has had no release since 2023 and pins a specific old nightly. `agent.md` forbids components without vendor support; `03-codificacao-segura.md` §11 forbids discontinued dependencies outright. | **Rejected.** Taint analysis is replaced by *making the taint unrepresentable* (Phase 2 newtypes) plus a mechanical gate over the driver call sites. `dylint` (maintained, Trail of Bits) is the optional AST-precise tier. |
| Kani on the permission engine directly | `ACL` holds `radix_trie::Trie<String, Permissions>` + `DashMap`, and `allow_operation` takes `&Request` — 25 fields including `Arc<dyn Storage>`, `Arc<dyn Handler>`, `Map<String, Value>`. Unbounded heap, trait objects, interior-mutability locks. | Kani cannot practically discharge that. Phase 3 **extracts a pure bounded core** (`agent.md`: "incremental extraction into `crates/`") and then makes production *use* it, so the proof is about shipped code. See §"The model-vs-code trap". |
| `decide(&[Rule], &Query)` over abstract-alphabet paths (Phase 3 sketch) | Production rules are strings in tries; an abstract-alphabet `decide` is a function production cannot call, i.e. a model. | `decide` is generic over the **index's answers** (`Ungated`, `Layer`, `Params`, `Caller` traits). Production instantiates it with the tries and the request; the proofs with free values for every answer — strictly more inputs than any policy produces. Path shapes are proved on the matcher production calls (`segments_match`), over the abstract alphabet. |
| 3-symbol alphabet `{A, B, C}` + `Plus` | Production depends on the empty segment (LIST paths end in `/`) and on string-prefix (`secret/fo*`). | `{Empty, A, Ab, B, Plus}`, with `A` a proper prefix of `Ab`: every relation the matcher can observe between two segments. |
| T1 "a *matching* deny ⇒ denied" | Vault precedence: a more specific grant (`secret/foo` read) beats a less specific deny (`secret/*` deny) by design. | T1 is stated for the deny that *governs* the path, or a gated/scoped deny that *applies*. |
| T4 "exact > segment-wildcard > prefix" | The non-exact order is by first-wildcard position, then literal tail, then fewer `+`, then length, then path; a prefix rule can beat a segment-wildcard rule. | T4 is stated as exact > trimmed exact (LIST) > the maximum of that order, which is strict and total. |
| T7 "a non-root ACL never yields `root_privs`" | `root_privs` is `sudo` on the evaluated rule, by design. | T7: `is_root` only from the root ACL; `root_privs` only from an evaluated `sudo`. |
| `KANI_VERSION: '0.56.0'` | 0.68.0 is what is installed (`make bootstrap`). | Verified with 0.68.0 / CBMC 6.11.0; Phase 4 pins that. |

## Findings that motivate this work

Discovered while scoping. Each is a concrete instance of the class its phase closes.

**Status: F2–F5 are fixed** (see `CHANGELOG.md` → `[Unreleased]` → Security). They were authorization-affecting defects in shipped code, so under `03` §10 they were closed as standalone fix PRs ahead of the phases — the phases exist to make the *next* one impossible, not to schedule these. F1 was open by design until Phase 1: v0.37.6 fixed its instances, and Phase 1 (`[Unreleased]`) removes the class — a privileged handler without the witness no longer registers. See § Compliance for the ones that need an incident/ESI path rather than a normal fix.

**F7–F8 are open; F6 is fixed (T119).** Phase 3's model checking and code reading found three evaluator findings, preserved and pinned by tests rather than fixed because Phase 3 was a no-behaviour-change refactor. F6 was authorization-affecting, so under `03` §10 it was closed ahead of further feature work, as F2–F5 were, as its own `Permissionamento` change with the `02` §6 change record (§ T119); the ESI notification is pending. Details of F7 and F8 are withheld from this repository until their fixes ship; the maintainer holds the write-up.

| # | Finding | Location | Class | Phase |
|---|---|---|---|---|
| F1 ✅ **closed structurally** (Phase 1) | 44 `sys` routes did privileged work inline and never crossed `pre_route` — fixed reactively in v0.37.6 by adding an `authorize_sys_request` call to each. The fix is a **convention**: a new handler that omits the call still compiles and still serves. | `src/http/sys.rs` | Missing structural guarantee | 1 |
| F2 ✅ **fixed** | `GET /metrics` had **no authorization at all** — no token, no ACL, no IP filter. It serves the Prometheus registry of a secrets vault (per-mount operation counters, cache hit rates, login counters) to any caller that can reach the listener. | [src/http/metrics.rs](src/http/metrics.rs) | Unauthenticated privileged read | Fixed ahead of Phase 1: cluster-local socket peer **or** a configured CIDR **or** a token with `read` on `sys/metrics`; else 403. New `metrics { ... }` config block. Phase 1 still owns making it structural. |
| F3 ✅ **fixed** | `list(prefix)` built `WHERE vault_key LIKE ?` with a bound `"{prefix}%"`. Binding prevents *syntax* injection but **not pattern semantics**: `_` is a single-character wildcard in a `LIKE` pattern. Vault keys routinely contain `_`, so listing `secret/my_app/` also matches `secret/myXapp/…`. | [src/storage/hiqlite/mod.rs](src/storage/hiqlite/mod.rs), [mysql_backend.rs](src/storage/mysql/mysql_backend.rs) | Over-return with authorization impact | Fixed ahead of 2.1 via Option A (escaped `LIKE` + `ESCAPE '\\'`), in `scan` as well as `list`, and in the MySQL backend. |
| F4 ✅ **fixed** | The over-returned rows were **not** filtered out downstream: `entry.vault_key.trim_start_matches(prefix)` is a no-op on a key that does not start with `prefix`, so the foreign key is pushed into the result verbatim. `trim_start_matches` also strips *repeated* prefixes (`secret/secret/x` → `x`), where `strip_prefix` is meant. | [src/storage/hiqlite/mod.rs](src/storage/hiqlite/mod.rs) | Missing post-condition | Fixed ahead of 2.1: `strip_prefix` is now the authoritative membership test on every returned row. |
| F5 ✅ **fixed** | The table identifier was `format!`-interpolated into every hiqlite statement, unvalidated, straight from config (`conf.get("table")`, default `vault`). One site is `client.batch(...)`, which executes multiple `;`-separated statements. Config is operator-controlled, so this is not remotely reachable — but this deployment templates config through Puppet/quadlets, and the shape is exactly a multi-statement injection. | [src/storage/hiqlite/mod.rs](src/storage/hiqlite/mod.rs) | Unvalidated identifier interpolation | Fixed ahead of 2.1 with a `validate_table_name` allow-list at construction (plain SQL identifier, ≤64 chars). `SqlIdent` in 2.1 supersedes it as a type-level guarantee. |
| F6 ✅ **fixed** (T119) — found by Kani in Phase 3.2 | On enforcement a `deny` did not beat a `groups`/`scopes`-qualified grant, and an applying qualified `deny` did not revoke. The operator-facing statement is the `[Unreleased]` Security entry. | `bv_policy_core::decide`; callers `PolicyStore::readable_targets`, `PolicyStore::may_connect_target` | Deny supremacy refuted on enforcement | Fixed after Phase 3 as its own change (§ T119). The Kani witness is now the theorem `t1_deny_wins_on_enforcement`. |
| F7 ❌ **open** (T120) — found by Kani in Phase 3.2 | Details are withheld from this repository until the fix ships; the maintainer holds the write-up. | `bv_policy_core::ungated_grants_list` | Withheld | Kani witness and differential tests pin the current behaviour. |
| F8 ❌ **open** (T121) — found reading the code for 3.4 | Details are withheld from this repository until the fix ships; the maintainer holds the write-up. | `grouped_rule_matches` / `scoped_rule_matches` | Withheld | Differential tests pin the current behaviour. |

**Sequencing consequence (discharged):** F2 and F3/F4 were authorization-affecting defects in shipped code. Under `03-codificacao-segura.md` §10 a grave finding is fixed *before* other work, so they shipped as phase-0 fix PRs rather than phase deliverables. What the phases still owe:

- Phase 1 must make the `/metrics` gate **structural** — it was a hand-written check in the handler, exactly the convention-not-guarantee shape F1 describes. Done: `metrics_routes::ScrapeAuthorized`.
- Phase 2.1 must fold `escape_like_prefix` / `validate_table_name` into `bv-sql-guard` so `SqlIdent` is the type-level version of the runtime allow-list now in place.

**Deviation from the 2.1 sketch below:** the sketch proposes returning `ErrPhysicalBackendPrefixInvalid` for a row that fails `strip_prefix`, on the reasoning that escaping makes such a row unreachable. It does not: SQLite's `LIKE` is ASCII-case-insensitive by default, so a key differing only in case legitimately matches the escaped pattern. Erroring there would break listing whenever two keys differ by case alone. The shipped code filters those rows instead, and the escaping remains a narrowing optimization rather than the membership test.

## The model-vs-code trap

The standard failure of "we formally verified our authorization engine" is that the verified artifact is a hand-written model that drifts from, or never was, the deployed code. This roadmap treats that as the primary risk and closes it in three steps, in order:

1. **3.2 proves the core.** Kani exhausts a bounded input space over `bv-policy-core::decide`.
2. **3.3 proves the core agrees with production.** Proptest generates policy sets + queries, runs both `ACL::allow_operation` and `decide`, and asserts identical verdicts. This finds drift but does not prevent it.
3. **3.4 removes the possibility of drift.** `Permissions::check` and the rule-layering loop in `allow_operation` delegate to `decide`. After 3.4, `bv-policy-core` is not a model of the evaluator — it *is* the evaluator, and the proofs are statements about production behaviour. Phase 3 is not Done until 3.4 lands.

Until 3.4, every claim must be phrased "proved for the core, differentially checked against production", never "the ACL is formally verified".

**3.4 has landed.** The accurate claim is now: "the ACL's decision is model-checked for the theorems and within the bounds listed in `docs/verification.md`; the index that feeds it is differentially tested, not proved". Still never "the ACL is formally verified" — F7 is a theorem the code does *not* satisfy (F6 was one until T119), and the proofs found them precisely because they are about the code that runs.

## Compliance mapping (FGV NRM / G-002)

This work is largely the *mechanization* of rules the FGV standard already imposes. Mapping is recorded here so the compliance report can cite it rather than re-deriving it.

| Norm rule | This roadmap |
|---|---|
| §5.3.1 — a **single** authentication/authorization point, foreseen in the design | Phase 1 makes the single point (`pre_route`) structurally unbypassable. F1/F2 are current deviations. |
| §5.3.5 / `03` §1 — parameterized queries always; allow-list where parameterization cannot reach (table/column names) | Phase 2. `SqlIdent` **is** the allow-list the rule prescribes. |
| §5.3.5 / `03` §8 — every endpoint authenticated, including read-only; IP filter where origin is predictable | F2 **closed**: `/metrics` now requires a token (`read` on `sys/metrics`) unless the caller satisfies the IP filter the rule itself sanctions — the existing `ip_is_cluster_local` predicate, judged on the socket peer, plus an operator-configured CIDR list. |
| `03` §10 / §5.3.7 — mandatory periodic source-code security verification; unsatisfactory versions must not be installed | Phase 4 tiers 0–3. The tier-3 verification report is the artifact for this rule. |
| §5.3.7 — a grave/critical open finding **blocks** new functionality | Recorded above as the phase-0 sequencing consequence for F2–F4. |
| `02` §6 — Login / Auditoria / Permissionamento / Método de autenticação are **componentes básicos de segurança** under reinforced change control, and the ESI verifies unauthorized changes | Every phase here touches one. Each PR needs the § Tracking change record, and the initiative needs ESI sign-off (below). |
| §5.3.6 / `02` §7–8 — every installed version generated from version control and tagged | Phase 4 tier 3 binds the verification report to the release tag. |

**Gates I cannot close — flag as explicit pendencies:**

- **ESI approval of the security premises** for this architecture change. Phase 1 and 3.4 alter `Permissionamento` and `Método de autenticação`, both componentes básicos: `02` §1 and NRM §5.4.2 require ESI involvement *before* the premise changes, not at review time.
- **ESI classification validation.** Proposed level: **4** — BastionVault stores credentials for other systems, so a compromise is a compromise of everything it fronts, and `01`'s heuristic puts credentials above the "dados pessoais sensíveis → 3" line. Level 4 forbids internet exposure and requires proven conformance in security tests before *any* version is installed, which is a material operational constraint. This is a **proposal subject to ESI validation**, not a decision.
- **Information gap:** the **Norma de Controle de Acessos** is not available to me. If it constrains how the ACL model may express authorization (e.g. mandatory profile/group indirection, per `02` §4), it may add invariants to the Phase 3 theorem list. Registered as a dependency; not invented.

---

## Phase 0 — Baseline: route inventory + threat model sign-off

**Objective:** know exactly what is being guaranteed, before building machinery to guarantee it.

### Prerequisites

- None. This is a read-only pass.

### Implementation steps

1. Enumerate every route reachable on the listener: `sys::init_sys_service`, `rustion_webhook`, `logical` (the `/v1/{path:.*}` catch-all), `metrics`, and `batch`. Record for each: path, methods, whether it reaches `Core::handle_request` (and therefore `pre_route`) or does its work inline, and the policy path it is judged on.
2. Classify each into exactly one of: `Privileged` (token + ACL required), `Tiered` (anonymous minimum, authenticated full — the `sys/info` shape shipped in v0.37.6), `PublicProbe` (deliberately anonymous, with a written justification), `ClusterLocal` (waived on socket peer, never on `X-Forwarded-For`).
3. Write the threat model paragraph for each non-`Privileged` entry: what an unauthenticated caller learns, and why that is acceptable. This is the text that lands in the golden file in 1.3.
4. File the phase-0 fix PRs for F2, F3, F4 (see § Findings). Keep them separate from the phase-1 refactor — `agent.md`: do not mix cleanup into security-sensitive changes.

### Definition of Done

- A table in this document listing every route and its class, with no `Unknown` rows.
- F2/F3/F4 fix PRs merged, each with a regression test proving the old behaviour cannot return.
- ESI premise-change request filed for phases 1 and 3.4.

### Inventory (as code)

The table this phase asks for is generated from the route table Phase 1.3 introduced, so it cannot drift from what is served, and lives in two checked-in files rather than in this document:

- `crates/bv-server/tests/golden/route-inventory.txt` — all 292 (method, path) rows the listener serves, each with its class and what it is judged on: the policy path and operation for a privileged route, the logical path for a routed shim, the written justification for everything else.
- `crates/bv-server/tests/golden/anonymous-routes.txt` — the 29 rows an anonymous caller can reach, with the threat-model paragraph (step 3) for each.

Both are compared on every `cargo nextest run -p bv-server --lib`; there is no `Unknown` class to put a row in. The four Phase 0 classes did not cover the listener as it is, so the table adds four, each reviewed in the golden file like the others:

| Class | Rows | Meaning |
|---|---|---|
| `privileged` | 95 | inline handler behind `Authorized<R>` — token + ACL before the body runs (48 markers, most served under `v1` and `v2`) |
| `routed` | 168 | HTTP shim that builds one logical request and dispatches it through `Core::handle_request`; `pre_route` judges it on the listed logical path |
| `routed-unauthenticated` | 4 | as `routed`, onto a path the system backend lists in `unauth_paths` (`sys/internal/ui/mounts[/…]`); a test checks the split against the router |
| `dispatch` | 4 | carries caller-chosen logical requests — the `/v1` and `/v2` catch-alls, `v2/sys/batch`, `/v2/mcp` — each judged by `pre_route` on its own path |
| `public-probe` | 15 | deliberately anonymous: `init`, `seal-status`, `health`, `unseal`, the RFC 9728 metadata document |
| `tiered` | 2 | `sys/info` |
| `cluster-local` | 3 | `sys/cluster-status` and `/metrics`: a token, or a waiver judged on the socket peer |
| `signature-verified` | 1 | the Rustion `recording.ready` webhook, authenticated by its body signature |

**Outstanding:** the ESI premise-change request for phases 1 and 3.4 (the third Definition of Done item above) is a human process; it has not been filed by this work and remains a pendency under § Compliance.

---

## Phase 1 — Structural API hardening

**Objective:** make "this handler serves privileged data without authorization" a type error at the route-registration site. A developer adding a route should have to *actively* declare it public, in a file that shows up in review.

### Prerequisites

- Phase 0 inventory complete (the route table in 1.3 is that inventory, as code).
- `authorize_sys_request` ([src/http/sys.rs:1421](src/http/sys.rs:1421)) stays the single chokepoint — Phase 1 does not reimplement authorization, it makes the existing call unskippable.

### Implementation steps

**1.1 — The witness type.** Three properties do the work: the extractor runs *before* the handler body (so no privileged code can precede it), the constructor is private (so no other module can forge one), and the type is generic over the route (so the policy path and operation cannot be mismatched).

```rust
// src/http/authz.rs — new module.

/// Compile-time description of a privileged route.
///
/// Implementors are zero-sized marker types, one per route. The trait binds
/// the route to the policy path *and* the operation it is judged on, so the
/// pair cannot drift apart the way two arguments to a function call can.
pub trait SysRoute: 'static {
    const OPERATION: Operation;

    /// The mount-relative policy path. Takes the matched request so routes
    /// with dynamic segments (`sys/export/{path}`) build the path they are
    /// actually authorized against, rather than a prefix that would grant
    /// more than the operator wrote.
    fn policy_path(req: &HttpRequest) -> Result<String, RvError>;
}

/// Proof that the current request cleared `pre_auth → check_token → post_auth`
/// for route `R`.
///
/// The private fields are the security property: no code outside this module
/// can construct one, so a handler that holds an `Authorized<R>` provably ran
/// after the chokepoint. `PhantomData<fn() -> R>` keeps the marker invariant
/// without making `Authorized` inherit `R`'s auto-traits.
pub struct Authorized<R: SysRoute> {
    policy_path: String,
    _route: PhantomData<fn() -> R>,
}

impl<R: SysRoute> Authorized<R> {
    /// The path the caller was actually cleared for. Handlers that need the
    /// dynamic segment should read it here rather than re-parsing the request:
    /// re-parsing is how a handler ends up acting on a path it was not judged on.
    pub fn policy_path(&self) -> &str {
        &self.policy_path
    }
}

impl<R: SysRoute> FromRequest for Authorized<R> {
    type Error = RvError;
    type Future = LocalBoxFuture<'static, Result<Self, RvError>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move {
            let core = req
                .app_data::<web::Data<Arc<Core>>>()
                .ok_or(RvError::ErrPermissionDenied)?
                .clone();
            let policy_path = R::policy_path(&req)?;
            // The one and only chokepoint (NRM §5.3.1). Denials are audited
            // inside it; this module adds no second authorization path.
            authorize_sys_request(&core, &req, &policy_path, R::OPERATION).await?;
            Ok(Authorized { policy_path, _route: PhantomData })
        })
    }
}
```

Route markers, declared next to their handler:

```rust
sys_route! {
    /// `POST /v{1,2}/sys/seal` — seals the vault. Sudo-gated via `root_paths`.
    SysSeal => Operation::Write, static "sys/seal";

    /// `GET /v{1,2}/sys/export/{path}` — mount export. Judged on the full
    /// path, so `sys/export/*` in a policy cannot be narrowed by accident.
    SysExport => Operation::Read, dynamic |req| {
        Ok(format!("sys/export/{}", req.match_info().query("path")))
    };
}
```

**1.2 — Migrate the handlers.** The diff per handler is small and mechanical, which matters: 44 of them.

```rust
// Before — nothing in the signature says this route is privileged, and the
// call that makes it so is one deletable line.
async fn sys_seal_request_handler(
    core: web::Data<Arc<Core>>,
    req: HttpRequest,
) -> Result<HttpResponse, RvError> {
    authorize_sys_request(&core, &req, "sys/seal", Operation::Write).await?;
    core.seal("").await?;
    Ok(response_ok(None, None))
}

// After — the witness is a parameter. Delete it and the handler no longer
// satisfies `privileged::<SysSeal, _, _>`; the *registration* fails to
// compile. There is no runtime path in which the body runs unauthorized.
async fn sys_seal_request_handler(
    _authz: Authorized<SysSeal>,
    core: web::Data<Arc<Core>>,
) -> Result<HttpResponse, RvError> {
    core.seal("").await?;
    Ok(response_ok(None, None))
}
```

For defence in depth on the highest-risk operations, push the witness one level down so the *inner* function demands it too — then even a hypothetical unguarded caller inside the crate cannot invoke it:

```rust
impl Core {
    /// Requires proof of authorization rather than trusting its caller. The
    /// witness is unforgeable outside `http::authz`, so this signature is a
    /// static guarantee that no in-crate path reaches a seal without one.
    pub async fn seal_authorized(&self, _authz: &Authorized<SysSeal>, token: &str)
        -> Result<(), RvError> { ... }
}
```

Apply this to the operations `02` §2 classifies as sensitive: seal, backup, restore, export, import, credential creation, permission changes.

**1.3 — Routes as data, anonymous surface as a golden file.** The witness stops a *handler* from skipping authorization. It does not stop someone registering a handler that never asks for a witness. Close that by making registration itself typed, and the route set enumerable:

```rust
/// Register a handler that cannot be *written* without a witness.
///
/// The enforcement is `H: Handler<(Authorized<R>, T)>`: actix only implements
/// `Handler` for functions whose argument tuple matches, so a handler missing
/// the witness in position 0 does not typecheck at this call site. Arities
/// above two nest the remaining extractors in `T` (actix implements
/// `FromRequest` for tuples).
pub fn privileged<R, H, T>(method: Method, handler: H) -> Route
where
    R: SysRoute,
    T: FromRequest + 'static,
    H: Handler<(Authorized<R>, T)>,
    H::Output: Responder + 'static,
{
    web::method(method).to(handler)
}

/// Every route under `/v{1,2}/sys`, as data. `configure_sys_routes` is
/// generated from this table, so a route that is registered but not listed
/// here cannot exist — and one that is listed carries its class in the type
/// system, where review can see it.
pub const SYS_ROUTES: &[SysRouteSpec] = &[
    SysRouteSpec::privileged::<SysSeal>("/seal", &[Method::POST]),
    SysRouteSpec::privileged::<SysBackup>("/backup", &[Method::POST]),
    // Anonymous surface. `public` and `tiered` *require* a justification
    // string; there is no constructor without one.
    SysRouteSpec::tiered(
        "/info",
        &[Method::GET],
        "callers need it before a token can exist; version/uptime/storage_type \
         require a live token — see v0.37.6",
    ),
    SysRouteSpec::public(
        "/health",
        &[Method::GET],
        "load-balancer probe; exposes only initialized/sealed/standby",
    ),
];

#[test]
fn anonymous_sys_surface_matches_golden_file() {
    let actual: Vec<String> = SYS_ROUTES
        .iter()
        .filter(|r| !r.requires_token())
        .map(|r| format!("{} {:?} — {}", r.path, r.methods, r.justification()))
        .collect();
    // Widening the unauthenticated surface now *requires* editing
    // tests/golden/anonymous-sys-routes.txt. That is a reviewable diff in a
    // file whose only purpose is to be reviewed — the control F1 lacked.
    assert_eq!(
        actual.join("\n"),
        include_str!("../../tests/golden/anonymous-sys-routes.txt").trim(),
    );
}
```

Cover the non-`sys` surfaces too: `metrics` (F2), `rustion_webhook` (signature-authenticated — a distinct class, so give it a `SignatureVerified` witness rather than forcing it into `Authorized`), and `batch`, whose sub-requests must each be judged individually.

### Definition of Done

- Every route in the Phase 0 inventory is registered through `privileged::<R>`, `public`, `tiered`, or `cluster_local`; `grep` finds no bare `.to(` inside `configure_sys_routes`.
- Deleting the `Authorized<R>` parameter from any migrated handler fails `cargo check`. Proved by a `trybuild` compile-fail case checked into the repo, so the guarantee itself is regression-tested.
- The golden file exists and matches; adding a route without listing it fails the inventory test.
- `authorize_sys_request` has exactly one caller: the `FromRequest` impl.
- F2 **resolved ahead of this phase** (`/metrics` requires a token, a cluster-local peer, or a configured CIDR). What Phase 1 owes is making that gate structural rather than a hand-written check inside the handler.
- Integration tests: for each of five sampled privileged routes, an unauthenticated request returns 403 and appears on the denial audit trail.
- CHANGELOG entry under `[Unreleased]` → Security, plus the `02` §6 change record for `Permissionamento`.

### Implementation record

Landed in `[Unreleased]`. Code: `crates/bv-server/src/authz.rs` (witness, `privileged` / `guarded`), `src/routes.rs` (table shapes, the one builder, the inventory), `src/sys/routes.rs` (the `sys` table), `metrics_routes::ScrapeAuthorized`, `rustion_webhook::SignatureVerified`, `tests/golden/`. The DoD, item by item:

- **Registration.** `init_service` registers `routes::LISTENER` and nothing else; every route is a `route!` entry whose arm is its class. `configure_sys_routes` no longer exists. The text gate is crate-wide: `routes::tests::no_route_is_registered_outside_the_route_builder` fails on any actix registration call (or hand-written `RouteSpec`) outside `routes.rs` / `authz.rs`, and `the_registration_gate_detects_raw_registration` shows it can fail.
- **Compile-fail.** `compile_fail` doctests in `authz.rs` (run by `make test-doc`): no witness, the witness of another route, a payload-reading argument beside the witness, and a forged witness — each beside a compiling positive case that differs by that one mistake.
- **Golden file.** `anonymous_surface_matches_golden_file` and `route_inventory_matches_golden_file` (`BV_BLESS_GOLDEN=1` regenerates both). `every_listed_route_is_served_by_its_own_resource` resolves every row through actix's own resource map, so a resource shadowed by an earlier wildcard fails.
- **One caller.** `authz::tests::authorize_sys_request_has_exactly_one_caller`.
- **F2 structural.** `/metrics` takes `ScrapeAuthorized` and is registered through `authz::guarded`; the same for the webhook's `SignatureVerified`.
- **Integration.** `authz::tests::unauthenticated_privileged_requests_are_refused_and_audited`: `GET sys/plugins`, `GET sys/scheduled-exports`, `POST sys/exchange/export`, `GET sys/plugins/quarantine`, `DELETE sys/plugins/{name}/grants` each return 403 and leave an audit entry with that path, operation and an error.

Deviations from the sketch above, each a decision rather than an omission:

| Sketch | Shipped | Why |
|---|---|---|
| `fn policy_path(req) -> Result<String, RvError>` per marker | `const POLICY_PATH` template; `{name}` filled from the route capture | One string is both the path judged and the path the inventory prints. It expands exactly as the handlers' `format!` + `unwrap_or("")` did; a test checks every template names only segments its route captures. |
| `trybuild` compile-fail case | `compile_fail` doctests | `trybuild` builds in its own target directory (`target/tests/trybuild`) — for `bv-server`, a cold build of the whole `bastion_vault` graph. Doctests link against the existing artefacts. Error codes are only checked on nightly, hence the positive control. |
| `H: Handler<(Authorized<R>, T)>`, extra extractors nested in `T` | `Args: StartsWith<Authorized<R>>`, arities 1–6, the rest `PayloadFree` | No handler has to nest its arguments in a tuple, and a handler cannot read the body behind the witness. |
| The witness never reads the body | `type Body = WithBody` routes have the witness read it first | Keeps the existing order (body read under the resource's limit, then authorization) and the HMAC-redacted body in a refusal's audit entry. |
| Every refusal audited | `DenialAudit::NotRecorded` on the 8 routes that never audited one (`seal`, `backup`, `restore`, `export`, `import`, three cluster calls) | Pure refactor. Recording them is a one-word change per marker — follow-up. |
| `Core::seal_authorized(&Authorized<SysSeal>, …)` push-down for `02` §2 operations | Not done | `Core` is in `bv-core`, two crates below `bv-server`. A witness defined there could not keep its constructor private to the authorization module, and an in-`bv-server` wrapper would be vacuous: the operations themselves (`backup::create`, `Core::seal`) stay callable from `bastion_vault`. Open item. |
| Classes `privileged` / `public` / `tiered` / `cluster_local` | Plus `routed`, `routed_unauthenticated`, `dispatch`, `signature_verified` | What the listener actually has; see Phase 0 → Inventory. |
| — | `sys/cluster-status` keeps its hand-written gate, declared `cluster_local` | Not in scope here; a witness like `/metrics`' is a follow-up. |

**Behaviour.** No route added, removed or reordered; status codes and bodies unchanged (the 65 existing `bv-server` lib tests pass unmodified, 77 with the new ones). Differences a reviewer should know about: a `/metrics` refusal now leaves the extractor as an `InternalError` wrapping the same response, so actix's logger notes it at debug level; and in an app missing a non-`Core` registration (`PreviewStore`, the metrics manager — never the case in `bvault server`) an unauthorized call may now get 403 where it got 500, because actix polls extractors together. Public API of `bv-server`: new modules `authz` and `routes`, 48 public marker types in `sys`, and `metrics_routes::metrics_handler` takes the witness — a `MINOR` bump for `bv-server` at the next release.

**`02` §6 change record — `Permissionamento`.** Change: the authorization call of the 48 inline `sys` handlers, the `/metrics` gate and the webhook signature check move from handler bodies into extractors; route registration becomes a table. Intended behavioural impact: none. Persisted formats, configuration, API paths: unchanged. Verification: the tests above plus the full `bv-server` suite. Rollback: revert; nothing to migrate. ESI: the premise-change request is still outstanding (§ Compliance).

---

## Phase 2 — SQL injection elimination

**Objective:** reduce the set of strings that can reach a SQL driver to *literals, optionally with validated identifiers substituted*. Make anything else require a named, greppable, justified escape hatch.

### Prerequisites

- Phase 0 fix for F3/F4 merged ✅ (the `LIKE` semantics fix is a behaviour fix and did not ride inside a type refactor).
- Agreement that `sqlx` stays out (see § Deviations).

### Implementation steps

**2.1 — `crates/bv-sql-guard`.** A new crate with no dependencies and `#![forbid(unsafe_code)]`. Narrow responsibility, per `agent.md`'s crate guidance; zero deps so it can be verified and audited independently of the workspace.

```rust
/// A validated SQL identifier (table or column name).
///
/// Parameterization cannot bind an identifier, so the FGV standard's
/// prescribed control is an allow-list (`03-codificacao-segura.md` §1). This
/// type *is* that allow-list, enforced at construction — so every
/// interpolation site downstream is interpolating something that provably
/// cannot terminate a statement or begin a new one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlIdent(String);

impl SqlIdent {
    /// Accepts `[A-Za-z_][A-Za-z0-9_]{0,62}` and nothing else. Quotes,
    /// semicolons, whitespace, comment markers, and non-ASCII are rejected
    /// rather than escaped: rejecting is checkable by inspection, escaping is
    /// dialect-dependent and therefore is not.
    pub fn new(raw: &str) -> Result<Self, SqlGuardError> {
        let mut chars = raw.chars();
        match chars.next() {
            Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
            _ => return Err(SqlGuardError::BadLeadingChar),
        }
        if raw.len() > 63 {
            return Err(SqlGuardError::TooLong);
        }
        if !chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(SqlGuardError::IllegalChar);
        }
        Ok(Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str { &self.0 }
}

/// A statement safe to hand to a driver. Deliberately has no `From<String>`
/// and no `Display`-based constructor: the only ways in are a literal, or a
/// literal plus validated identifiers.
pub struct Sql(Cow<'static, str>);

#[macro_export]
macro_rules! sql {
    // `$lit:literal` is the enforcement — a runtime `String` does not match
    // this fragment specifier, so `sql!(user_input)` is a *parse* error.
    ($lit:literal) => { $crate::Sql::from_literal($lit) };
    ($lit:literal, $($ident:expr),+ $(,)?) => {
        $crate::Sql::from_literal_with_idents($lit, &[$($ident),+])
    };
}
```

**Also in 2.1, the F3/F4 fix.** Two options; take the first.

```rust
// Option A (recommended) — keep LIKE, disable its pattern language for the
// characters that are data here. Minimal diff, obviously correct by
// inspection, dialect-portable.
//
// LIKE treats `_` and `%` as wildcards *in the pattern*, and binding the
// pattern does not change that: `list("secret/my_app/")` also matched
// `secret/myXapp/…`, and those rows were returned verbatim because
// `trim_start_matches` is a no-op on a key that does not start with the
// prefix. Vault keys routinely contain `_`; the caller was authorized for one
// prefix, not both.
fn escape_like(prefix: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + 8);
    for c in prefix.chars() {
        if matches!(c, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

let stmt = sql!(
    "SELECT vault_key, vault_value FROM {} WHERE vault_key LIKE ? ESCAPE '\\'",
    &self.table,
);
let params = vec![Param::from(format!("{}%", escape_like(prefix)))];

// Option B — half-open range. Index-friendlier and has no pattern language at
// all, but the upper bound must be the byte-successor of the prefix under the
// column's collation; `prefix + '\u{10FFFF}'` is *not* a correct bound for
// keys that themselves contain U+10FFFF. Only take this with a collation test.

// And regardless of option, enforce the post-condition the old code assumed:
let Some(rest) = entry.vault_key.strip_prefix(prefix) else {
    // Unreachable once the pattern is escaped — which is exactly why it is
    // worth asserting rather than silently returning a foreign key.
    return Err(RvError::ErrPhysicalBackendPrefixInvalid);
};
```

Note `strip_prefix` replaces `trim_start_matches`, fixing the repeated-prefix bug in F4 as a side effect.

**2.2 — Migrate the backends.**

```rust
pub struct HiqliteBackend {
    client: hiqlite::Client,
    table: SqlIdent,   // was: String
    // ...
}

// At init — validate once, at the boundary, and fail loudly. An invalid
// `table` in config is now a startup error with a legible message, not a
// statement fragment.
let table = SqlIdent::new(conf.get("table").and_then(|v| v.as_str()).unwrap_or("vault"))
    .map_err(|e| RvError::ErrString(format!("storage config 'table' is not a valid SQL identifier: {e}")))?;

async fn put(&self, entry: &BackendEntry) -> Result<(), RvError> {
    // ... size guard unchanged ...
    self.client
        .execute(
            sql!("INSERT OR REPLACE INTO {} (vault_key, vault_value) VALUES (?, ?)", &self.table).into_cow(),
            vec![Param::from(entry.key.clone()), Param::from(entry.value.clone())],
        )
        .await
        .map_err(map_hiqlite_error)?;
    Ok(())
}
```

The `client.batch(...)` site (F5) is the one that could execute multiple statements; it gets the same treatment, and a comment recording that `batch` is multi-statement so future edits know the stake. The three Diesel `sql_query` sites already bind their values and keep their literal statements; they only need the wrapper for uniformity.

**2.3 — The mechanical gate.** The type system prevents the *easy* mistake; the gate catches a call that bypasses the wrapper entirely. Semgrep first: no Rust-toolchain coupling, runs in seconds, and this environment already has a Semgrep integration.

```yaml
# .semgrep/sql-guard.yml
rules:
  - id: bv-unguarded-sql-statement
    languages: [rust]
    severity: ERROR
    message: >-
      SQL statement built outside bv-sql-guard. Use sql!("...") — a literal,
      optionally with SqlIdent substitution. If you genuinely need a
      constructed statement, use Sql::escape_hatch_reviewed with a
      justification and add it to docs/sql-escape-hatches.md.
    patterns:
      - pattern-either:
          - pattern: $C.execute($S, ...)
          - pattern: $C.query_consistent_map($S, ...)
          - pattern: $C.batch($S)
          - pattern: diesel::sql_query($S)
      - pattern-not: $C.$M($crate_sql, ...)      # already a Sql
      - metavariable-pattern:
          metavariable: $S
          pattern-either:
            - pattern: format!(...)
            - pattern: $A + $B
            - pattern: $X.to_string()
```

Escape hatch, if one is ever needed:

```rust
impl Sql {
    /// Build a statement from a runtime string. Every call must appear in
    /// `docs/sql-escape-hatches.md` with a reviewer and a date; a CI check
    /// asserts the call sites and the document agree. Named to be ugly on
    /// purpose — this is the only unproved SQL in the tree.
    pub fn escape_hatch_reviewed(stmt: String, justification: &'static str) -> Self { ... }
}
```

**2.4 — Optional: `dylint`.** If the Semgrep rules prove too coarse (false positives on non-SQL `execute`), replace them with a `dylint` lint that resolves the callee's `DefId` and so fires only on real driver calls. Maintained, but it pins a nightly for the driver — take it only if 2.3 measurably misfires. Do not adopt on speculation.

### Definition of Done

- `grep -rn 'format!("SELECT\|format!("INSERT\|format!("DELETE\|format!("UPDATE\|format!("CREATE' src/ crates/` returns nothing.
- Every driver call site takes a `Sql`; `docs/sql-escape-hatches.md` is empty (target) or every entry has a reviewer and date.
- `bv-sql-guard` has unit tests for `SqlIdent` rejecting: empty, leading digit, `vault; DROP TABLE x`, `vault"`, `vault--`, `vault ` (trailing space), a 64-char name, and a non-ASCII homoglyph.
- `escape_like` has a test asserting `list("secret/my_app/")` does **not** return a key planted at `secret/myXapp/`, and the post-condition check is exercised by a test that plants a foreign key directly in the backend.
- `sql!(some_runtime_string)` is a compile error — checked in as a `trybuild` compile-fail case.
- The Semgrep ruleset runs in CI tier 0 and is red on a deliberately reintroduced `format!` statement (verify once, then revert).
- CHANGELOG under `[Unreleased]` → Security for F3/F4; → Changed for the refactor.

---

## Phase 3 — Formal verification of the permission engine (Kani)

**Objective:** prove that the ACL decision function's security invariants hold for **every** input in a bounded model — and then make that verified function the one production runs.

### Prerequisites

- Phases 1–2 done: they remove the "authorization was never consulted" and "storage returned the wrong keys" failure modes, so a proof about the decision function is a proof about something that actually gates access. Verifying the evaluator while a handler can bypass it is theatre.
- `cargo install --locked kani-verifier && cargo kani setup`. Kani ships its own toolchain; contributors need no nightly. Supported on `x86_64-unknown-linux-gnu` and `aarch64-apple-darwin`, which covers the dev Macs and CI.
- Read `src/modules/policy/{acl.rs,policy.rs}` end to end. The subtleties that matter — deny wiping the bitmap and clearing `granting_policies`, the LIST carve-out for group-gated rules, `scopes` resolution against `asset_owner` / `target_shared_caps` — are the theorems, and they are only in the code.

### Implementation steps

**3.1 — Extract `crates/bv-policy-core`.** Bounded, `no_std`, `#![forbid(unsafe_code)]`, zero dependencies.

The design decision that makes verification tractable: **abstract the path alphabet instead of the path strings.** Concrete strings are the wrong input space — what determines the verdict is the *shape* of the match (exact vs. segment-wildcard vs. prefix, and which rule wins), not the bytes. A 3-symbol alphabet over 4 segments lets Kani enumerate every shape exhaustively, which is strictly stronger than fuzzing a billion strings.

```rust
#![no_std]
#![forbid(unsafe_code)]

pub const MAX_RULES: usize = 4;
pub const MAX_SEGMENTS: usize = 4;

/// One path segment in the abstract alphabet. `A`/`B`/`C` are three
/// distinguishable concrete segments — enough to express "same", "different",
/// and "a third thing", which is all any path-matching predicate can observe.
/// `Plus` is the policy-side single-segment wildcard.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Seg { A, B, C, Plus }

/// Same bit layout as `Capability::to_bits()` in the host crate. Kept in sync
/// by an assertion in the host's test suite, not by comment.
pub const CAP_DENY: u32 = 1 << 0;
pub const CAP_LIST: u32 = 1 << 5;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub path: [Seg; MAX_SEGMENTS],
    pub is_prefix: bool,
    pub caps: u32,
    pub groups: GroupSet,          // bitset; empty == ungated
    pub scopes: ScopeSet,          // empty == unscoped
    pub required_params: ParamSet,
    pub denied_params: ParamSet,
    pub allowed_params: Option<ParamSet>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Query {
    pub path: [Seg; MAX_SEGMENTS],
    pub op: Op,
    pub target_groups: GroupSet,
    pub caller_is_owner: bool,
    pub shared_caps: u32,
    pub params: ParamSet,
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Decision {
    pub allowed: bool,
    pub caps: u32,
    pub root_privs: bool,
    pub list_filter_groups: GroupSet,
    pub list_filter_scopes: ScopeSet,
}

/// Total function, no allocation, no panics. Mirrors the layering in
/// `ACL::allow_operation`: exact → segment-wildcard → prefix, then
/// group-gated rules, then scope-filtered rules, with deny short-circuiting.
pub fn decide(rules: &[Rule], q: &Query) -> Decision { /* ... */ }
```

**3.2 — Harnesses.** One per theorem. Each names the invariant, and each is paired with a vacuity guard.

```rust
#[cfg(kani)]
mod proofs {
    use super::*;

    /// T1 — **deny supremacy.** No combination of rules, group membership,
    /// scopes, or parameters produces a grant when a matching rule denies.
    /// This is the invariant `allow_operation` implements by clearing the
    /// bitmap and returning early; here it is proved rather than reviewed.
    #[kani::proof]
    #[kani::unwind(MAX_RULES + 2)]
    fn deny_always_wins() {
        let rules: [Rule; MAX_RULES] = kani::any();
        let q: Query = kani::any();
        kani::assume(rules.iter().all(Rule::is_well_formed));

        // Vacuity guard: without this, an over-strong `assume` above would
        // make the harness pass by proving nothing at all. `cover` fails the
        // run if the interesting case is unreachable.
        kani::cover!(rules.iter().any(|r| r.matches(&q.path) && r.caps & CAP_DENY != 0));

        let d = decide(&rules, &q);

        if rules.iter().any(|r| r.matches(&q.path) && r.caps & CAP_DENY != 0) {
            assert!(!d.allowed, "a matching deny rule produced a grant");
            assert_eq!(d.caps, CAP_DENY, "deny did not clear the capability bitmap");
            assert!(d.list_filter_groups.is_empty());
        }
    }

    /// T2 — **fail-closed.** No matching rule ⇒ no capability. The default
    /// must be denial, not "whatever the previous branch left in `base`".
    #[kani::proof]
    #[kani::unwind(MAX_RULES + 2)]
    fn no_rule_means_no_grant() {
        let rules: [Rule; MAX_RULES] = kani::any();
        let q: Query = kani::any();
        kani::assume(rules.iter().all(|r| !r.matches(&q.path)));
        kani::cover!(true);

        let d = decide(&rules, &q);
        assert!(!d.allowed);
        assert_eq!(d.caps, 0);
        assert!(!d.root_privs);
    }

    /// T5 — **group-gate soundness.** A group-gated rule contributes nothing
    /// to a non-LIST request whose target is outside the rule's groups.
    #[kani::proof]
    #[kani::unwind(MAX_RULES + 2)]
    fn group_gate_is_sound() {
        let rules: [Rule; MAX_RULES] = kani::any();
        let q: Query = kani::any();
        kani::assume(q.op != Op::List);
        kani::assume(rules.iter().all(|r| !r.groups.is_empty()));
        kani::assume(rules.iter().all(|r| r.groups.intersection(q.target_groups).is_empty()));
        kani::cover!(rules.iter().any(|r| r.matches(&q.path)));

        assert!(!decide(&rules, &q).allowed);
    }

    /// T5b — the LIST carve-out cannot silently widen into an unfiltered
    /// grant. `allow_operation` deliberately grants a gated LIST and defers
    /// to a post-route filter; the invariant that makes that safe is that the
    /// filter set is *never* empty on such a grant. Prove it, because an empty
    /// filter set means "return everything".
    #[kani::proof]
    #[kani::unwind(MAX_RULES + 2)]
    fn gated_list_always_carries_a_filter() {
        let rules: [Rule; MAX_RULES] = kani::any();
        let mut q: Query = kani::any();
        q.op = Op::List;
        kani::assume(rules.iter().all(|r| !r.groups.is_empty()));  // gated only
        kani::cover!(decide(&rules, &q).allowed);

        let d = decide(&rules, &q);
        if d.allowed {
            assert!(!d.list_filter_groups.is_empty(),
                    "gated LIST granted with no filter — would return every key");
        }
    }
}
```

Full theorem list for 3.2:

| # | Theorem | Why it is the security property |
|---|---|---|
| T1 | Deny supremacy | The single invariant operators rely on when writing a deny rule. |
| T2 | Fail-closed default | An unmatched path must never inherit a grant from evaluation order. |
| T3 | Grant monotonicity | Adding a non-deny rule never *removes* a capability; catches merge bugs in `Permissions::merge`. |
| T4 | Specificity precedence + determinism | Exact > segment-wildcard > prefix, and the winner is unique — so the verdict does not depend on trie iteration order. |
| T5 | Group-gate soundness | `groups = [...]` cannot be bypassed. |
| T5b | Gated-LIST filter non-emptiness | The carve-out cannot degrade into "return everything". |
| T6 | Scope-gate soundness | `scopes = ["owner"]` grants only to the owner; `["shared"]` only for capabilities actually present in `target_shared_caps`. |
| T7 | Root isolation | `root` short-circuits to allowed; a non-root ACL can never yield `is_root` or `root_privs`. |
| T8 | Parameter constraints | Missing `required_parameters` ⇒ denied (this is what makes `required_parameters = ["env"]` enforceable); a parameter in `denied_parameters` ⇒ denied; `allowed_parameters` non-empty and the parameter absent ⇒ denied. |

**3.3 — Differential equivalence.** In the host crate, with `std` and `proptest`:

```rust
proptest! {
    /// The verified core and the production evaluator must agree on every
    /// generated policy set. This is the anti-drift net until 3.4 removes the
    /// possibility of drift entirely.
    #[test]
    fn core_and_production_agree(model in arb_policy_model(), q in arb_query()) {
        let acl = ACL::new(&model.to_policies())?;
        let produced = acl.allow_operation(&model.to_request(&q), false)?;
        let proved   = bv_policy_core::decide(&model.to_rules(), &q.to_core());

        prop_assert_eq!(produced.allowed, proved.allowed);
        prop_assert_eq!(produced.capabilities_bitmap, proved.caps);
        prop_assert_eq!(produced.list_filter_groups.is_empty(), proved.list_filter_groups.is_empty());
    }
}

/// Guards the "same bit layout" comment in bv-policy-core.
#[test]
fn capability_bit_layout_matches_core() {
    assert_eq!(Capability::Deny.to_bits(), bv_policy_core::CAP_DENY);
    assert_eq!(Capability::List.to_bits(), bv_policy_core::CAP_LIST);
    // ... every variant
}
```

**3.4 — Production delegates to the core.** `Permissions::check` and the rule-layering in `allow_operation` reduce to: translate `(ACL, Request)` into `(&[Rule], Query)`, call `decide`, translate the `Decision` back. The trie/DashMap stay — they are the *index* that selects candidate rules; the *decision* is the verified function. This is the step that turns "we verified a model" into "we verified the code", and it is why Phase 3 is not Done without it.

### Definition of Done

- `cargo kani -p bv-policy-core` reports `VERIFICATION:- SUCCESSFUL` for all of T1–T8, with `SUCCESSFUL` on every `cover` too. A `cover` reported `UNSATISFIABLE` fails the phase — it means the harness proved nothing.
- Explicit `#[kani::unwind(n)]` on every harness, and a documented reason for each bound. No harness relies on a default.
- No `UNDETERMINED` or timeout results. A harness that cannot be discharged is either simplified or recorded in this document as an explicit non-guarantee — never left silently unfinished.
- 3.3 proptest suite green at ≥100k cases, with any counterexample it found recorded in the CHANGELOG as a fixed defect.
- 3.4 landed: `ACL::allow_operation` calls `bv_policy_core::decide`, and deleting the core crate breaks the host build.
- `docs/verification.md` states, in operator-facing language: what is proved, the bounds (`MAX_RULES = 4`, `MAX_SEGMENTS = 4`, 3-symbol alphabet), and **what is therefore not proved** — policies with more than 4 rules matching one path, real string matching in the trie index, the async `post_auth` resolution of `asset_groups` / `asset_owner` / `target_shared_caps`, and everything upstream of the evaluator. An overclaimed guarantee is worse than none.
- ESI notified: this changes `Permissionamento`, a componente básico (`02` §6).

### Implementation record

The record below captures Phase 3 when it landed, before T119 fixed F6. The
current harness set and guarantees are recorded at the top of this roadmap,
in `docs/verification.md`, and in the T119 record below.

3.1, 3.3 and 3.4 landed in `[Unreleased]`; 3.2's harnesses landed and run green, but two theorems as the code's comments state them are refuted (F6, F7), so 3.2 stays open until T119 and T120. Code: `crates/bv-policy-core` (`check.rs`, `decide.rs`, `gate.rs`, `path.rs`, `rank.rs`, `merge.rs`; `model.rs` + `proofs.rs` under `cfg(kani)`), `crates/bv-kernel/src/modules/policy/core_bridge.rs` (the host side), `differential/` (3.3). The DoD, item by item:

- **Kani.** `cargo kani -p bv-policy-core` (Kani 0.68.0, CBMC 6.11.0, default solver, 4 min 10 s wall on an M-series Mac): `Complete - 18 successfully verified harnesses, 0 failures, 18 total`; 34 of 34 covers `SATISFIED`, none `UNSATISFIABLE` or `UNDETERMINED`. Per harness:

  | Harness | Theorem | Result | Covers | Time |
  |---|---|---|---|---|
  | `t1_deny_wins_in_capability_probes` | T1 | SUCCESSFUL | 3/3 | 10.5 s |
  | `t1_a_governing_deny_grants_nothing` | T1 | SUCCESSFUL | 1/1 | 8.8 s |
  | `f6_enforcement_lets_a_layered_grant_override_deny` | F6 witness | SUCCESSFUL (defect present) | 2/2 | 10.2 s |
  | `t2_no_rule_means_no_grant` | T2 | SUCCESSFUL | 2/2 | 8.2 s |
  | `t3_merge_keeps_deny_and_never_drops_a_capability` | T3 (+T1 merge) | SUCCESSFUL | 3/3 | 0.1 s |
  | `t3_an_added_layered_grant_never_removes_a_capability` | T3 | SUCCESSFUL | 2/2 | 23.0 s |
  | `t4_exact_rules_take_precedence` | T4 | SUCCESSFUL | 2/2 | 0.4 s |
  | `t4_specificity_is_a_strict_total_order` | T4 | SUCCESSFUL | 1/1 | 0.5 s |
  | `t4_the_most_specific_candidate_wins_in_any_order` | T4 | SUCCESSFUL | 2/2 | 100.7 s |
  | `t4_segment_wildcards_match_by_shape` | T4 | SUCCESSFUL | 2/2 | 2.6 s |
  | `t5_group_gate_is_sound` | T5 | SUCCESSFUL | 1/1 | 5.0 s |
  | `t5_t6_a_failed_gate_contributes_nothing` | T5, T6 | SUCCESSFUL | 1/1 | 35.4 s |
  | `t6_scope_gate_is_sound` | T6 | SUCCESSFUL | 4/4 | 1.9 s |
  | `t5b_gated_list_always_carries_a_filter` | T5b | SUCCESSFUL | 1/1 | 4.8 s |
  | `t5b_an_unfiltered_list_needs_an_ungated_list_grant` | T5b | SUCCESSFUL | 1/1 | 6.7 s |
  | `f7_a_non_governing_list_rule_drops_the_filter` | F7 witness | SUCCESSFUL (defect present) | 1/1 | 5.1 s |
  | `t7_root_isolation` | T7 | SUCCESSFUL | 1/1 | 10.6 s |
  | `t8_parameter_constraints` | T8 | SUCCESSFUL | 4/4 | 0.4 s |

  Re-run on the final (formatted) tree: identical results, 3 min 51 s; no check inside a harness is `UNREACHABLE` (the 106 that are sit in Kani's library models and in model helpers a given harness does not call). The first run failed `t8` on `unwinding assertion loop 0` (a 6-element well-formedness scan under `unwind(5)`); the scan was rewritten as one mask test. That is the bound check working, not a relaxed bound.
- **Unwind.** Every harness carries `#[kani::unwind(5)]` = bound + 1, with the reason in the `proofs.rs` header; none relies on a default.
- **No undischarged results.** None. The two refuted theorems are not left as failing harnesses: each is a *defect witness* that `cover`s the counterexample (Kani prints it), turns `UNSATISFIABLE` — failing the gate — once fixed, and names the `assert` that replaces it.
- **3.3.** `production_agrees_with_the_frozen_evaluator`: 100 000 cases green in 82 s (`PROPTEST_CASES=100000`, fixed seed), every case 1–3 generated HCL policies × 1–4 requests × both modes, comparing verdict, bitmap, `root_privs`, granting-policy names, LIST filters and their order, `capabilities()`, `has_mount_access`, the scope diagnostics and the built index; plus `segment_matcher_agrees_with_the_frozen_one` and `capability_bit_layout_matches_core`. The oracle is `differential/legacy.rs`, a verbatim copy of the evaluator before it delegated, so "no behaviour change" is checked rather than asserted. No counterexample was found, so there is no fixed defect to record from it; F6 and F7 came from the model checker.
- **3.4.** `ACL::allow_operation` is `bv_policy_core::decide` over `core_bridge`'s index adapters; `Permissions::check` is `bv_policy_core::check`; `Permissions::merge` and `ACL::new` take the deny decision from `merge_caps`; `WcPathDescr`'s order is `bv_policy_core::compare` and the winner `MostSpecific`; both segment matchers are `segments_match`. Deleting the crate breaks `bv-kernel`. No existing test was modified: `cargo nextest run -p bv-kernel --lib policy` passes 103 (8 of them new), and the whole `bv-kernel` lib suite passes.
- **`docs/verification.md`.** Written (S108): what is proved, the bounds, and § "What is not proved".
- **ESI.** Not notified by this work — a human process; outstanding with Phase 1's request (§ Compliance).

Deviations from the sketch above (see also § Deviations, where the theorem restatements are):

| Sketch | Shipped | Why |
|---|---|---|
| `decide(&[Rule; 4], &Query)` with paths in the abstract alphabet | `decide` generic over the index's answers; a separate path matcher proved over the alphabet | Production must call the proved function. Quantifying over every answer the index could give is a superset of every policy set. |
| "One harness per theorem", 8 harnesses | 18: several per theorem, plus two defect witnesses | T1, T3, T4, T5b split where the statement has independent halves; the witnesses keep refuted theorems visible without a red gate that would hide new failures. |
| `MAX_RULES = 4` rules in total | 4 per layer (gated, scoped) plus 3 ungated candidates | The layers are evaluated independently; a total of 4 could not put a deny and a grant in both. |
| Deny supremacy proved outright (T1) | At Phase 3 landing, proved for probes and ungated rules and refuted on enforcement with layers (F6); fixed later by T119 | The proof is about production, so the behaviour change was kept out of the no-behaviour-change refactor and delivered separately. |
| `Permissions::check` / layering only | Also the specificity order, the segment matcher, the merge's deny decision | They decide which rule governs (T4) and whether two rules combine (T3); leaving them in the host would leave T3/T4 about a model. |

**Behaviour.** None intended, none found: the differential suite above and the unmodified policy tests. Two performance notes: the non-exact lookup clones a candidate's permissions only for matching rules (as before) and selects in one pass instead of sorting; `allow_operation` now normalises the path before the root/`help` short-circuits (one extra allocation on those requests).

**`02` §6 change record — `Permissionamento`.** Change: the ACL decision moves into `bv-policy-core`; the kernel keeps the rule index. Intended behavioural impact: none. Persisted formats, configuration, API paths: unchanged. Verification: Kani (above), the differential suite, the `bv-kernel` policy suite. Rollback: revert; nothing to migrate. ESI: outstanding. F6–F8 are recorded, not changed.

---

## T119 — Close F6: deny supremacy on enforcement

**`02` §6 change record — `Permissionamento`.**

| Field | Record |
|---|---|
| Version / classification | `[Unreleased]`; no release tag or publication date assigned. Proposed FGV level 4, subject to ESI validation as recorded in § Compliance. |
| Change / requester | Close the authorization finding F6 under T119, requested by the maintainer as a security fix. |
| Component and owner | `Permissionamento`; the officially responsible person for versioning the component remains a human ownership field and is not assigned by this change. |
| What changes | A governing `deny`, and a `groups`- or `scopes`-qualified `deny` whose qualifier applies, refuse enforcement even when another layer grants the path. Per-target read and connect gates resolve target qualifiers before treating an unqualified grant as conclusive. |
| Where | `bv-policy-core`'s decision core; `bv-kernel` policy ACL bridge, per-target filtering and connect gate; the Kani inventory and verification documentation. |
| Resulting changes | Requests, resource-search results and session-connect checks that previously escaped an overlapping applicable `deny` are refused. Capability probes keep their existing result. No persisted format, configuration schema or API shape changes. |
| Verification | Regression tests over real HCL and stored group/share facts; the 100,000-case differential; complete `bv-policy-core` Kani run (18/18); component check, clippy and lib tests; affected-package L3 (903 passed, 13 skipped across six binaries). |
| Rollback | Revert the change; there is no data or configuration migration. Review policies with overlapping qualified rules before rollback because it would restore the authorization bypass. |
| ESI | **Pending human action:** notify and obtain the required ESI verification before publication. This record does not close that gate. |

---

## Phase 4 — CI/CD orchestration

**Objective:** run all three guarantees continuously, within a per-PR budget of minutes, and emit the periodic-verification artifact `03-codificacao-segura.md` §10 requires.

### Prerequisites

- Phases 1–3 landed (or landing incrementally — each tier can be switched on as its phase completes).
- Awareness of two local constraints: the repo's workflows are currently `.disabled`, and `cargo audit` is blocked because the **workspace** cannot resolve a lockfile (vanilla `russh` and `sspi` pin incompatible RustCrypto pre-releases). This is not an obstacle — it is an argument for the phase structure. `bv-policy-core` and `bv-sql-guard` have **zero dependencies**, so they resolve, build, and verify in CI even while the workspace does not.

### Implementation steps

**Tiering.** Cost rises with tier; feedback latency rises with it too. Never put a slow check where a fast one suffices.

| Tier | When | Contents | Budget |
|---|---|---|---|
| 0 | every push, and `make verify-fast` locally | `cargo clippy -p bv-policy-core -p bv-sql-guard -- -D warnings`; Semgrep SQL ruleset; route-inventory + golden-file tests; `trybuild` compile-fail cases; `cargo test -p bv-policy-core -p bv-sql-guard` | < 60 s |
| 1 | every PR | Tier 0 + `cargo kani -p bv-policy-core --harness` over the fast set (T1, T2, T5, T7) + the 3.3 proptest suite at 10k cases | < 8 min |
| 2 | nightly + `workflow_dispatch` | Full harness set at full bounds, `--solver cadical` for the heavy ones, `kani::cover` coverage report, proptest at 1M cases | < 60 min |
| 3 | release tag | Tier 2 + generate and attach `verification-report.md` | — |

```yaml
# .github/workflows/verify.yml
name: Formal Verification

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 4 * * *'      # tier 2
  workflow_dispatch:

env:
  CARGO_TERM_COLOR: always
  KANI_VERSION: '0.56.0'     # pinned: an unpinned verifier makes the result unreproducible

jobs:
  tier0:
    name: tier 0 — lints, gates, unit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
        with: { components: clippy }
      # Only the dependency-free crates. The full workspace cannot resolve a
      # lockfile today (russh/sspi RustCrypto pre-release conflict), which is
      # precisely why the verified core lives in its own crate.
      - run: cargo clippy -p bv-policy-core -p bv-sql-guard --all-targets -- -D warnings
      - run: cargo test -p bv-policy-core -p bv-sql-guard
      - uses: semgrep/semgrep-action@v1
        with: { config: .semgrep/sql-guard.yml }

  kani:
    name: tier 1 — model checking
    runs-on: ubuntu-latest
    needs: tier0
    steps:
      - uses: actions/checkout@v4
      # Kani's toolchain is ~1 GB; caching it is the difference between a
      # 2-minute job and a 12-minute one.
      - uses: actions/cache@v4
        with:
          path: ~/.kani
          key: kani-${{ env.KANI_VERSION }}-${{ runner.os }}
      - run: |
          cargo install --locked kani-verifier --version "$KANI_VERSION"
          cargo kani setup
      - name: Verify (fast harness set)
        if: github.event_name == 'pull_request'
        run: |
          cargo kani -p bv-policy-core --output-format terse \
            --harness deny_always_wins \
            --harness no_rule_means_no_grant \
            --harness group_gate_is_sound \
            --harness root_isolation
      - name: Verify (full)
        if: github.event_name != 'pull_request'
        run: cargo kani -p bv-policy-core --output-format terse --solver cadical

      # A harness silently disappearing is the failure mode this guards. Kani
      # cannot fail a proof that no longer exists, so assert the inventory.
      - name: Assert harness inventory
        run: |
          expected=8
          actual=$(grep -c '#\[kani::proof\]' crates/bv-policy-core/src/proofs.rs)
          test "$actual" -eq "$expected" || {
            echo "::error::harness count changed: $actual != $expected — update docs/verification.md and this gate together"
            exit 1
          }
```

**Local parity.** The project deliberately keeps tests on the developer machine, so CI must not be the only way to run this:

```makefile
verify-fast: ## Tier 0 — lints, SQL gate, route inventory, unit tests (<60s)
	cargo clippy -p bv-policy-core -p bv-sql-guard --all-targets -- -D warnings
	cargo test -p bv-policy-core -p bv-sql-guard
	semgrep --config .semgrep/sql-guard.yml --error src/ crates/

verify: verify-fast ## Tier 1 — + Kani fast harness set + differential proptest
	cargo kani -p bv-policy-core --output-format terse --harness deny_always_wins ...
	cargo test --lib policy::differential -- --include-ignored

verify-full: ## Tier 2 — every harness at full bounds (slow; nightly in CI)
	cargo kani -p bv-policy-core --solver cadical
```

**Failure policy.** Written down because the wrong default silently voids the whole exercise:

- `FAILURE` → block the merge. A counterexample is a real bug; Kani prints the concrete input.
- `UNDETERMINED` / timeout → **block**, do not warn. Treating an undischarged proof as a pass is the same as not having it.
- `UNSATISFIABLE` on a `cover` → block. The harness is vacuous.
- Kani version bump → its own PR, with the full tier-2 run green before merge. Never bundled with a code change.

**Tier 3 — the release artifact.** `03` §10 asks for periodic source-code security verification, and `02` §7–8 tie every installed version to a tag. Emit the evidence:

```markdown
# Verification Report — BastionVault v0.39.0

Commit: <sha>   Tag: v0.39.0   Date: <iso8601>
Kani 0.56.0 · CBMC 5.95.1 · solver: cadical

## Structural (Phase 1)
Routes registered: 118 · privileged 112 · tiered 2 · public 3 · cluster-local 1
Anonymous surface golden file: MATCH
trybuild compile-fail cases: 4/4 as expected

## SQL (Phase 2)
Driver call sites: 11 · guarded 11 · escape hatches 0
Semgrep bv-unguarded-sql-statement: 0 findings

## Formal (Phase 3)
| Harness | Result | Cover | Unwind | Time |
|---|---|---|---|---|
| deny_always_wins | SUCCESSFUL | SATISFIED | 6 | 41 s |
| ...

Bounds: MAX_RULES=4, MAX_SEGMENTS=4, |alphabet|=3.
Not covered: see docs/verification.md § Limits.
```

### Definition of Done

- `verify.yml` green on `main`, and tier 1 green on every PR.
- Tier-1 wall clock under 8 minutes with a warm Kani cache; measured, not assumed.
- A deliberately introduced ACL bug (e.g. `|=` instead of the deny short-circuit) is caught by tier 1, with the counterexample in the job log. Verify once on a scratch branch — an unexercised gate is not a gate.
- `make verify` reproduces tier 1 locally on macOS and Linux.
- Tier 3 report generated for one release and attached to the tag.
- `docs/verification.md` published, including the § Limits section.
- CHANGELOG under `[Unreleased]` → Added, referencing this roadmap.

### Implementation record

Landed in `[Unreleased]`. Code: `Makefile` § Verification tiers (`verify-gates`, `verify-routes`, `verify-fast`, `verify-kani`, `verify-differential`, `verify`, `verify-full`, `verification-report`); `scripts/verify.py` (recorded steps, the Kani gate and its self-test, the report); `scripts/kani-harnesses.txt` (harness inventory and the pinned verifier); `.github/workflows/verify.yml` and `.github/actions/setup-kani/`; `scripts/ci-plan.sh` / `scripts/test-changed.sh` (`run_kani`, `run_differential`, `verify_files`). No product code, configuration, persisted format or API changed. What the tiers contain and the gate's failure policy are in `docs/verification.md` § Continuous verification.

Measured locally (Apple M-series, warm `target/`, Kani 0.68.0 / CBMC 6.11.0; Semgrep is not installed on this machine, so every run is `SEMGREP=0` and records that step `SKIPPED`):

| Run | Wall | Result |
|---|---|---|
| `cargo kani -p bv-policy-core` (all 18, for the fast-set split) | 239 s | 18/18 `SUCCESSFUL`, 34/34 covers `SATISFIED`, no `UNREACHABLE` check inside a harness |
| `make verify-fast SEMGREP=0` | 33 s | every step `PASS`, Semgrep `SKIPPED` (`routes` 25 tests, witness doctests 5) |
| `make verify SEMGREP=0` (tier 1) | 146 s | `PASS`: Kani fast set 15/15 in 92 s with F6 and F7 reported as known open findings; differential at 10 000 cases 8/8 |
| `make verify-differential CASES=1000000`, proptest's default reject budget | 200 s | **FAIL** — both property tests aborted with "Too many local rejects" (the `+*` filter; 183 701 accepted cases before the abort). No disagreement. See the deviation below |
| `make -k verify-full SEMGREP=0` (tier 2), reject budget scaled | 2 109 s | `PASS`, Semgrep `SKIPPED`: Kani full set 18/18 in 245 s with F6 and F7 as known open findings; differential at 1 000 000 cases 8/8 in 851 s of test time, after 9 min 40 s rebuilding the `bv-kernel` test harness (see the follow-up on `build.rs`) |

The DoD, item by item:

- **`verify.yml` green on `main`, tier 1 on every PR — open.** The workflow has never run: it is uncommitted. What was checked without a runner: the YAML parses, every `run:` script passes `bash -n`, the plan step's event logic was dry-run for each trigger, the `required` job's script against success / skipped / failure / cancelled inputs, and `scripts/ci-plan.sh` against four seeds (`run_kani` only for `bv-policy-core` and the tooling; `run_differential` for anything that reaches `bv-kernel`).
- **Tier-1 wall clock under 8 min with a warm Kani cache — local only.** 146 s on the machine above. Runner time is unmeasured, and a PR's differential job also pays a `bv-kernel` test build from the `build` cache.
- **A deliberate ACL bug caught by tier 1 — done locally, not on a scratch branch through CI.** `d.caps = CAP_DENY` → `d.caps |= CAP_DENY` in the layer wipe (`decide.rs`, the roadmap's example), in a copy of the crate outside the tree: the fast set fails `t1_deny_wins_in_capability_probes` and the gate exits 1 naming the harness and the failing check. The counterexample's input is **not** in the log: Kani 0.68.0's concrete playback generated tests for the three satisfied covers only (the failing `assert_eq!` has a runtime-formatted message and fails inside `core::panicking`), and CBMC's own `--trace` is 780 000 lines. The gate prints the playback test when Kani produces one and says so when it does not. A second mutant — dropping `d.allowed = false` from the wipe — survived and is equivalent: probes never report `allowed` (`check.rs`), and on enforcement the wipe is unreachable because a deny rule's check reports no capability, which is F6.
- **`make verify` reproduces tier 1 on macOS and Linux — macOS only.** Not run on Linux.
- **Tier-3 report for one release, attached to the tag — open.** `make verification-report` was run against the tier-1 evidence above: it rendered the real Kani fast-set result (per-harness table, F6/F7 as known open findings, bounds, route classes) and, once the tree had been edited, marked every record `STALE` and dropped the harness table rather than reporting it. It has not been run on tier-2 evidence: a second tier-2 run on the final tree was stopped, and its start had already replaced the tier-0 records and removed the earlier Kani record, so `target/verify/` holds no complete set. On this machine it can reach no tier anyway (Semgrep `SKIPPED` ⇒ verdict `INCOMPLETE`, the rule working), and the uncommitted tree is marked `DIRTY — not a release artifact`. No release was cut.
- **`docs/verification.md` published, with the limits** — § Continuous verification added; linked from `docs/_sidebar.md`, where it was missing.
- **CHANGELOG** — `[Unreleased]` → Added.

Deviations from the sketch above:

| Sketch | Shipped | Why |
|---|---|---|
| Workflows are `.disabled`; the workspace cannot resolve a lockfile | `verify.yml` is active, like `tests.yml`; Kani runs inside the workspace | Both prerequisites are stale: `tests.yml` runs and builds the workspace. `cargo kani -p bv-policy-core` resolves it from `Cargo.lock`, so the Kani job restores the registry cache. |
| `KANI_VERSION: '0.56.0'` in the workflow | `pin kani 0.68.0` / `pin cbmc 6.11.0` in `scripts/kani-harnesses.txt` | One pin, read by the gate (which refuses other versions), the CI install and the report. |
| `--solver cadical` for the heavy harnesses | no solver flag | CaDiCaL is Kani 0.68's default; the flag would also silently override any future per-harness `kani::solver`. |
| Fast set T1, T2, T5, T7 | 14 of 18 harnesses: every one ≤ 20 s | Re-measured after T119: the enforcement theorem costs 29.5 s and moved to the slow set; the 14 fast harnesses cost 72.4 s, the four slow ones 169.3 s, and the complete run took 219 s wall. Every theorem T1–T8 and the remaining witness retain a fast harness. |
| `grep -c '#[kani::proof]'` == 8 | a manifest of names, kinds, sets and cover counts | A count misses a rename, and a deleted cover is the other silent failure. Checked statically (names, explicit unwind) and against every run. |
| `--output-format terse`, exit status | regular output, parsed by the gate | `cargo kani` exits 0 on an `UNSATISFIABLE` cover, and terse output does not name covers. |
| Tier 0 in CI = clippy + tests + Semgrep | `make verify-gates SEMGREP=0` | Semgrep is already `tests.yml`'s required `sql-guard` job and the `bv-server` route checks its `Unit bv-server` job; not run twice. Tier 3 runs both. |
| Route inventory in tier 0 | in local tier 0 (`verify-routes`), plus the `Authorized<R>` `compile_fail` doctests | ~20 s on a warm tree, so it fits; the doctests are the Phase 1 compile-fail cases (the sketch's `trybuild`). |
| `cargo test --lib policy::differential -- --include-ignored` | `PROPTEST_CASES=N cargo nextest run -p bv-kernel --lib differential` | The suite is not `#[ignore]`d; the case count is the knob. |
| Proptest at 1M cases | 1M, with `PROPTEST_MAX_LOCAL_REJECTS = max(65536, CASES)` | The default budget aborts at ~184k cases (the `+*` filter rejects ~6.7 % of rule-path draws). Scaling it keeps every accepted case and still aborts when rejects outnumber them. The cleaner fix — a generator that never draws `+*` — is the Phase 3 suite's, not changed here. |
| "`kani::cover` coverage report" | the per-harness cover table, in the gate's output and the report | Kani's source coverage (`-Z source-coverage`) is unstable. |
| Tier 3 on a release tag | on `releases/*` | The namespace `standalone-release.yml` and `macos-release.yml` publish GitHub releases under; the same create-or-upload step, retried for their race. |
| A report template | generated from per-step evidence, each bound to the commit and a fingerprint of any uncommitted change | A report must not claim a check it did not see: no record is `NOT RUN`, another tree's record is `STALE`. |

Follow-ups: the first CI run (runner timings, the two new cache keys, Kani setup on `ubuntu-latest`); the scratch-branch mutant through CI; making **All verification checks** a required status in branch protection (a repository setting); the differential generator drawing no `+*`; whether `make test-release` should run `verify-full`, which would also change `AGENTS.md` § 4; and the root `build.rs`, which prints no `cargo:rerun-if-changed`, so cargo reruns it — and rebuilds `bastion_vault` and every test harness above it — after an edit to *any* file of the root package, docs and scripts included. The warm-tree timings above assume no such edit; with one, `verify-routes` and `verify-differential` pay that rebuild (seconds to ~10 min measured).

---

## Cross-cutting decisions, made up front

- **No new runtime dependencies.** `bv-policy-core` and `bv-sql-guard` have none. Kani, Semgrep, `proptest`, `trybuild`, and any `dylint` are dev/CI only and never enter a shipped binary. This keeps `agent.md`'s trusted-computing-base rule intact and keeps the verified crates auditable in isolation.
- **Verification code is `#[cfg(kani)]`-gated**, so it does not affect normal builds, `cargo check` time, or the binary.
- **Bounds are explicit and published.** Every `unwind` and every `MAX_*` appears in `docs/verification.md` with the reason. A bound chosen to make a proof pass, undocumented, is a lie by omission.
- **Two crates, not one.** `bv-policy-core` (authorization) and `bv-sql-guard` (persistence) have unrelated failure modes and different reviewers. `agent.md`: narrow responsibilities, minimal dependency surfaces.
- **Phases 1 and 2 land as pure refactors** with no behaviour change, so their diffs are reviewable as "did the guarantee get added" rather than "did the semantics change". Behaviour fixes (F2–F4) ship as separate PRs *first*.
- **Kani version is pinned** in `verify.yml` and in `docs/verification.md`. An unpinned verifier makes a verification claim unreproducible.

## What this does not cover

Stated explicitly so the guarantee is not read more broadly than it is.

- **Cryptography.** No proofs about the barrier, ML-KEM/ML-DSA usage, or the Shamir implementation. Different tooling (HACL*-style, or constant-time analysis) and a separate initiative.
- **The token lifecycle.** `check_token`, TTL, renewal, and revocation are upstream of the evaluator and unverified. A proof that the ACL decides correctly says nothing about whether the identity handed to it is genuine.
- **The async resolution feeding the evaluator.** `asset_groups`, `asset_owner`, and `target_shared_caps` are resolved in `post_auth` against storage. Phase 3 proves the decision is correct *given* those inputs; it does not prove they are resolved correctly.
- **The trie index.** Phase 3 verifies rule *selection semantics* over an abstract alphabet, not `radix_trie`'s correctness on real strings. Mitigated by 3.3 differential testing, not proved.
- **Concurrency.** Kani harnesses are single-threaded. `DashMap` interleavings in `granting_policies_map` are out of scope.
- **The HTTP layer below the extractor.** Actix's routing, TLS, and payload handling are trusted.
- **Anything about the GUI or the CLI.**

## Tracking

Per `CLAUDE.md`:

- `ROADMAP.md` — registered under Core as *Formal Verification & Type-Driven Security* (`[ ]` Todo), and listed as a next-up initiative.
- `CHANGELOG.md` — the phase-0 fix PRs (F2–F5) shipped in **v0.38.6** with Security entries. Phase 2 has its entry under Changed and Phase 1 under Security, both in `[Unreleased]`; each remaining phase adds its own entry on completion.
- Update the Status table above as sub-phases complete. A phase is Done only when every sub-phase is — Phase 3 in particular is **not** Done at 3.2, however good the Kani output looks (see § The model-vs-code trap).
- Every PR touching `Login`, `Auditoria`, `Permissionamento`, or `Método de autenticação` needs the `02` §6 change record and an ESI signal in its compliance report.
