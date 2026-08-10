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
| 0 | Baseline: route inventory + threat model sign-off | `[ ]` Todo |
| 1 | Structural API hardening (`Authorized<R>` witness + route table) | `[ ]` Todo |
| 1.1 | `SysRoute` trait + `Authorized<R>` extractor | `[ ]` Todo |
| 1.2 | Migrate the 44 inline `sys` handlers to the witness | `[ ]` Todo |
| 1.3 | Route table as data + anonymous-surface golden file | `[ ]` Todo |
| 2 | SQL injection elimination (`SqlIdent` / `Sql` + lint gate) | `[ ]` Todo |
| 2.1 | `bv-sql-guard` crate + `LIKE`-pattern fix | `[/]` In progress — `LIKE`-pattern + table-identifier fixes shipped (F3/F4/F5); the `SqlIdent` / `Sql` crate is still Todo |
| 2.2 | Migrate hiqlite + MySQL backends to the guarded API | `[ ]` Todo |
| 2.3 | Mechanical gate (Semgrep ruleset), escape-hatch registry | `[ ]` Todo |
| 2.4 | Optional: `dylint` AST lint replacing the text gate | `[ ]` Todo |
| 3 | Formal verification of the permission engine (Kani) | `[ ]` Todo |
| 3.1 | Extract `bv-policy-core` (bounded, `no_std`, pure) | `[ ]` Todo |
| 3.2 | Kani harnesses T1–T8 + vacuity guards | `[ ]` Todo |
| 3.3 | Differential equivalence vs. production `ACL` (proptest) | `[ ]` Todo |
| 3.4 | Production delegates to the verified core | `[ ]` Todo |
| 4 | CI/CD orchestration + release verification report | `[ ]` Todo |

## Deviations from the original brief

Recorded up front, per `agent.md`'s "explain assumptions clearly".

| Brief said | Reality in this repo | Decision |
|---|---|---|
| **SQLx** for query hardening | `sqlx` was **removed** from the project (`libsqlite3-sys` link conflict — see `roadmap.md`, Storage: `[~] Removed`). Persistence is hiqlite (raw SQL + `Param` binding) and Diesel/MySQL (query builder + three `sql_query` sites). | Do **not** reintroduce `sqlx`. It would resurrect a known build break and violate `agent.md`'s dependency rules for zero gain — the existing drivers already parameterize values. Phase 2 targets the two real gaps: interpolated **identifiers** and `LIKE`-pattern semantics. |
| **Axum** or Actix extractors | `actix-web 4.13` (`src/http/mod.rs`). | Actix `FromRequest` is the extractor mechanism. The witness pattern below is framework-idiomatic for both, so a future migration keeps the guarantee. |
| **MIRAI** for taint analysis | MIRAI has had no release since 2023 and pins a specific old nightly. `agent.md` forbids components without vendor support; `03-codificacao-segura.md` §11 forbids discontinued dependencies outright. | **Rejected.** Taint analysis is replaced by *making the taint unrepresentable* (Phase 2 newtypes) plus a mechanical gate over the driver call sites. `dylint` (maintained, Trail of Bits) is the optional AST-precise tier. |
| Kani on the permission engine directly | `ACL` holds `radix_trie::Trie<String, Permissions>` + `DashMap`, and `allow_operation` takes `&Request` — 25 fields including `Arc<dyn Storage>`, `Arc<dyn Handler>`, `Map<String, Value>`. Unbounded heap, trait objects, interior-mutability locks. | Kani cannot practically discharge that. Phase 3 **extracts a pure bounded core** (`agent.md`: "incremental extraction into `crates/`") and then makes production *use* it, so the proof is about shipped code. See §"The model-vs-code trap". |

## Findings that motivate this work

Discovered while scoping. Each is a concrete instance of the class its phase closes.

**Status: F2–F5 are fixed** (see `CHANGELOG.md` → `[Unreleased]` → Security). They were authorization-affecting defects in shipped code, so under `03` §10 they were closed as standalone fix PRs ahead of the phases — the phases exist to make the *next* one impossible, not to schedule these. F1 remains open by design: v0.37.6 fixed its instances, and Phase 1 removes the class. See § Compliance for the ones that need an incident/ESI path rather than a normal fix.

| # | Finding | Location | Class | Phase |
|---|---|---|---|---|
| F1 | 44 `sys` routes did privileged work inline and never crossed `pre_route` — fixed reactively in v0.37.6 by adding an `authorize_sys_request` call to each. The fix is a **convention**: a new handler that omits the call still compiles and still serves. | `src/http/sys.rs` | Missing structural guarantee | 1 |
| F2 ✅ **fixed** | `GET /metrics` had **no authorization at all** — no token, no ACL, no IP filter. It serves the Prometheus registry of a secrets vault (per-mount operation counters, cache hit rates, login counters) to any caller that can reach the listener. | [src/http/metrics.rs](src/http/metrics.rs) | Unauthenticated privileged read | Fixed ahead of Phase 1: cluster-local socket peer **or** a configured CIDR **or** a token with `read` on `sys/metrics`; else 403. New `metrics { ... }` config block. Phase 1 still owns making it structural. |
| F3 ✅ **fixed** | `list(prefix)` built `WHERE vault_key LIKE ?` with a bound `"{prefix}%"`. Binding prevents *syntax* injection but **not pattern semantics**: `_` is a single-character wildcard in a `LIKE` pattern. Vault keys routinely contain `_`, so listing `secret/my_app/` also matches `secret/myXapp/…`. | [src/storage/hiqlite/mod.rs](src/storage/hiqlite/mod.rs), [mysql_backend.rs](src/storage/mysql/mysql_backend.rs) | Over-return with authorization impact | Fixed ahead of 2.1 via Option A (escaped `LIKE` + `ESCAPE '\\'`), in `scan` as well as `list`, and in the MySQL backend. |
| F4 ✅ **fixed** | The over-returned rows were **not** filtered out downstream: `entry.vault_key.trim_start_matches(prefix)` is a no-op on a key that does not start with `prefix`, so the foreign key is pushed into the result verbatim. `trim_start_matches` also strips *repeated* prefixes (`secret/secret/x` → `x`), where `strip_prefix` is meant. | [src/storage/hiqlite/mod.rs](src/storage/hiqlite/mod.rs) | Missing post-condition | Fixed ahead of 2.1: `strip_prefix` is now the authoritative membership test on every returned row. |
| F5 ✅ **fixed** | The table identifier was `format!`-interpolated into every hiqlite statement, unvalidated, straight from config (`conf.get("table")`, default `vault`). One site is `client.batch(...)`, which executes multiple `;`-separated statements. Config is operator-controlled, so this is not remotely reachable — but this deployment templates config through Puppet/quadlets, and the shape is exactly a multi-statement injection. | [src/storage/hiqlite/mod.rs](src/storage/hiqlite/mod.rs) | Unvalidated identifier interpolation | Fixed ahead of 2.1 with a `validate_table_name` allow-list at construction (plain SQL identifier, ≤64 chars). `SqlIdent` in 2.1 supersedes it as a type-level guarantee. |

**Sequencing consequence (discharged):** F2 and F3/F4 were authorization-affecting defects in shipped code. Under `03-codificacao-segura.md` §10 a grave finding is fixed *before* other work, so they shipped as phase-0 fix PRs rather than phase deliverables. What the phases still owe:

- Phase 1 must make the `/metrics` gate **structural** — today it is a hand-written check in the handler, exactly the convention-not-guarantee shape F1 describes.
- Phase 2.1 must fold `escape_like_prefix` / `validate_table_name` into `bv-sql-guard` so `SqlIdent` is the type-level version of the runtime allow-list now in place.

**Deviation from the 2.1 sketch below:** the sketch proposes returning `ErrPhysicalBackendPrefixInvalid` for a row that fails `strip_prefix`, on the reasoning that escaping makes such a row unreachable. It does not: SQLite's `LIKE` is ASCII-case-insensitive by default, so a key differing only in case legitimately matches the escaped pattern. Erroring there would break listing whenever two keys differ by case alone. The shipped code filters those rows instead, and the escaping remains a narrowing optimization rather than the membership test.

## The model-vs-code trap

The standard failure of "we formally verified our authorization engine" is that the verified artifact is a hand-written model that drifts from, or never was, the deployed code. This roadmap treats that as the primary risk and closes it in three steps, in order:

1. **3.2 proves the core.** Kani exhausts a bounded input space over `bv-policy-core::decide`.
2. **3.3 proves the core agrees with production.** Proptest generates policy sets + queries, runs both `ACL::allow_operation` and `decide`, and asserts identical verdicts. This finds drift but does not prevent it.
3. **3.4 removes the possibility of drift.** `Permissions::check` and the rule-layering loop in `allow_operation` delegate to `decide`. After 3.4, `bv-policy-core` is not a model of the evaluator — it *is* the evaluator, and the proofs are statements about production behaviour. Phase 3 is not Done until 3.4 lands.

Until 3.4, every claim must be phrased "proved for the core, differentially checked against production", never "the ACL is formally verified".

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

- `roadmap.md` — registered under Core as *Formal Verification & Type-Driven Security* (`[ ]` Todo), and listed as a next-up initiative.
- `CHANGELOG.md` — **no entry yet.** Nothing here changes behaviour until the phase-0 fix PRs (F2–F4) land; those get `[Unreleased]` → Security entries, and each phase adds its own on completion.
- Update the Status table above as sub-phases complete. A phase is Done only when every sub-phase is — Phase 3 in particular is **not** Done at 3.2, however good the Kani output looks (see § The model-vs-code trap).
- Every PR touching `Login`, `Auditoria`, `Permissionamento`, or `Método de autenticação` needs the `02` §6 change record and an ESI signal in its compliance report.
