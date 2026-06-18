# Feature: Namespaces / Multi-tenancy

## Summary

Add Vault-compatible **hierarchical namespaces** so a single BastionVault deployment can host many tenants — teams, business units, customers — with strong isolation between them. A namespace is an addressable container that has its own mounts, policies, identities, tokens, audit devices, and quotas; it nests under a parent namespace and inherits nothing automatically.

The HTTP surface follows Vault Enterprise's: every endpoint accepts an `X-BastionVault-Namespace: <path>` header (or a path prefix `/<ns>/v1/...`); operators with the right policy in the parent namespace can create, list, and delete child namespaces; tokens are bound to the namespace they were issued in and can optionally be made *child-visible* for delegated administration.

## Motivation

- **Today's "Partial" state mixes three ideas under one row.** What ships is *user-level* scoping — per-user ownership ([features/per-user-scoping.md](per-user-scoping.md)), asset groups, resource groups, sharing. What does **not** ship is *tenant-level* isolation: an MSP, a SaaS company, or any organisation with hard departmental boundaries cannot today host two tenants in one BastionVault and prove the blast radius of a stolen token is bounded to its tenant. Namespaces are the missing layer.
- **Vault parity is required for every enterprise migration.** Customers running Vault Enterprise rely on namespaces for per-team isolation and for chargeback. Without them, BastionVault is an SMB-tier product even when its crypto and audit story are stronger than Vault's.
- **Cleaner operational model than per-mount RBAC.** Today every isolation boundary is encoded in policy strings (`path "team-a/*" { ... }`). That works for a few teams; at twenty it becomes a mess of overlapping wildcards. Namespaces hoist isolation up a level: instead of a policy that lists every team-a path, you have an `admin` policy *inside* the team-a namespace that means nothing in team-b's.
- **Quotas and rate limits become tractable.** A per-namespace quota ("team-a may hold at most 10k secrets, may issue at most 100 leases/min") is straightforward to enforce; the equivalent across path-prefix policies is an exercise in regex and despair.

## Current State

> **Phases 1–4 functionally complete.** `src/modules/namespace/` implements the
> namespace container + registry (`store.rs`), the request→namespace resolver
> (`router.rs` — header *and* path-prefix forms), the per-namespace mount-router
> registry (`mount_registry.rs`) with end-to-end mount creation + dispatch, the
> idempotent **non-destructive** barrier re-root copy (`migrate.rs`),
> namespace-bound tokens + `child_visible` (`token_binding.rs`), per-login
> namespace binding (userpass/approle), cross-namespace policy-path refusal
> (`policy_scope.rs`), the cross-tenant identity-link primitive
> (`identity_link.rs`, `v2/sys/namespace-links`), and counting + rate quota
> enforcement (`quota.rs`). Per-namespace **policy storage** lives in
> `src/modules/policy/policy_store.rs` (tenant ACL keyspaces + namespace-aware
> ACL compilation); per-namespace **audit broadcasters** + the root superuser
> mirror live in `src/audit/broker.rs`; per-namespace **identity** (entities,
> aliases, groups) lives in `src/modules/identity/`. CRUD is exposed under
> `v2/sys/namespaces`; a management GUI ships at the Namespaces page. The
> implicit root namespace is minted on first unseal.
>
> **Re-root activation is the unconditional default for every install** — no
> opt-in. `namespaces/<root_uuid>/…` is the live root from first unseal on new
> installs; existing installs migrate automatically on the next unseal (the
> non-destructive copy + verify runs eagerly and the prefix flips only if it
> verifies, else it retries next boot — unseal is never blocked). All six quotas
> are enforced and a GUI namespace switcher ships.
>
> **In progress (Phase 5):** per-principal **namespace assignment**
> (login-restriction) — restrict which namespaces a credential may authenticate
> into, across all auth backends, unrestricted by default. See the "Namespace
> Assignment (Login-Restriction)" design section and the Phase 5 scope table.
>
> **Remaining follow-ups:**
> - **`cert`-login** namespace binding, and **tenant self-service of `sys/*`**
>   (today reachable only by root/sudo tokens carrying the namespace header).
> - A recursive GUI namespace **tree + rename** (the page lists root children
>   flat; server-side rename is also not yet implemented).
> - **Namespace-scoped auth mounts** (per-tenant credentials) — the larger
>   alternative to Phase 5's login-restriction model; deferred.
>
> **API-prefix note:** the spec below shows `/v1/sys/namespaces` for Vault
> parity, but per `agent.md` all new routes ship under `v2/`; the management
> endpoints are therefore reached at `v2/sys/namespaces`. The
> `X-BastionVault-Namespace` header applies to existing `v1` logical paths
> (backward-compatible addressing), which is permitted. As of **0.15.1** the
> namespace + namespace-link routes are wired into `configure_sys_routes`
> (`src/http/sys.rs`) and served under **both** `/v1/sys` and `/v2/sys`: they
> originally lived only on the sys backend's logical route table, so over HTTP
> the explicit `/v1/sys` actix scope 404'd them before the `/v1/{path:.*}`
> catch-all could handle them (they worked only in embedded vault mode). The
> remote GUI defaults to the `/v1` prefix, so this is what made the Namespaces
> page 404 against a remote server.

- **`namespace` keywords already appear in the auth path code** (e.g. `src/modules/credential/saml/verify.rs`, `src/modules/credential/oidc/path_roles.rs`, `src/modules/policy/acl.rs`). These are SAML/OIDC *protocol* namespaces (XML namespaces, claim namespaces), **not** the multi-tenant namespace concept this spec adds. Search hits there are unrelated to multi-tenancy.
- **What ships today as "Partial":**
  - **Per-user scoping** — owner + share model with two baseline roles, ACL templating (`{{username}}`, `{{entity.id}}`), shared-resource scope, ownership-transfer admin endpoints, full GUI Sharing page. See [features/per-user-scoping.md](per-user-scoping.md).
  - **Asset groups** ([features/asset-groups.md](asset-groups.md)) and **resource groups** ([features/resource-groups.md](resource-groups.md)) — let operators bundle resources/files for shared access without per-item grants.
  - **Identity entities + groups** in `src/modules/identity/` — all flat under one root.
  - **Mount table** is single-rooted; every mount path lives in one shared namespace.
- **What does not ship:**
  - No tenant container above mounts.
  - No per-tenant policy / token / mount table.
  - No per-tenant audit broadcaster.
  - No `X-BastionVault-Namespace` header handling.
  - No quota / rate-limit primitive scoped to a tenant.

The "Partial" status accurately reflects that BastionVault has *intra-tenant* scoping (within one shared root) but lacks *inter-tenant* isolation.

## Design

### Namespace Model

A namespace is identified by a slash-delimited path: `root` (implicit), `engineering`, `engineering/platform`, `engineering/platform/secops`. Each namespace has:

- A **UUID** (the storage key; the path is mutable, the UUID is not).
- A **parent UUID** (root = `nil`).
- A **mount table** scoped to it.
- A **policy store** scoped to it.
- An **identity store** (entities, aliases, groups) scoped to it.
- A **token store** scoped to it.
- An **audit broadcaster set** scoped to it.
- A **quota set** (storage bytes, lease count, request rate).
- A **child set** (other namespaces parented to it).

Namespaces **inherit nothing automatically.** A token in `engineering/platform` cannot read a secret in `engineering` unless the parent namespace exposes a mount or policy that explicitly delegates. This is the same model Vault Enterprise uses and the only model that makes the blast-radius story honest.

### Storage Layout

```
namespaces/
  <uuid>/
    config.json                 # name, parent_uuid, created_at, quotas
    mounts/                     # per-namespace mount table
    policies/                   # per-namespace policies
    identity/                   # entities, aliases, groups
    tokens/                     # per-namespace token store
    audit/                      # per-namespace audit broadcaster config
    children                    # set of child uuids
```

The barrier-encrypted storage prefix `LOGICAL_BARRIER_PREFIX` (see [docs/secret-engines.md](../docs/docs/secret-engines.md)) is reorganised so every existing prefix becomes `namespaces/<root_uuid>/...`. Migration writes the root namespace at registration time and re-roots existing data; the migration is idempotent and runs once on upgrade.

### Request Routing

Two equivalent forms (Vault parity):

1. **Header**: `X-BastionVault-Namespace: engineering/platform` on a request to `/v1/secret/foo` resolves to the `secret/` mount in the `engineering/platform` namespace.
2. **Path prefix**: `/v1/engineering/platform/secret/foo` (no header) routes to the same mount.

The router resolves namespace path → UUID via a small cache (LRU, refreshed on namespace mutation); then performs the standard mount-prefix match within that namespace's mount table; then dispatches to the backend exactly as today (per [docs/secret-engines.md](../docs/docs/secret-engines.md)).

A request that omits both forms targets the root namespace.

### Token Binding

Every token carries a `namespace_id` field. The token can be used:

- In its issuing namespace (always).
- In a **child** namespace, *only if* the token is marked `child_visible = true` and the child's policy permits the calling identity. This lets a parent admin operate inside a child without a separate login.
- In a **parent** or **sibling** namespace: never. Cross-namespace requests with a non-`child_visible` token return `permission_denied`.

`child_visible` is opt-in per token; default is `false`. The flag is set at create-time and immutable.

### Policy Model

Policies are namespace-scoped. A policy named `admin` in `engineering` and a policy named `admin` in `marketing` are unrelated documents. Within a policy, `path "..."` rules match paths *within the same namespace*; cross-namespace path references are syntactically refused at policy-write time with an error pointing at the namespace-spanning path.

Templated policies (the existing `{{username}}` / `{{entity.id}}` / `{{auth.mount}}` from per-user scoping) gain `{{namespace.path}}` and `{{namespace.id}}` for advanced use cases.

### Identity Model

Each namespace has its own identity tree. An entity in `engineering` is a *different entity* from one in `marketing`, even if both are aliased to the same external SSO subject. This is the right default — one company's "alice" SSO claim shouldn't grant her anything in another customer's namespace just because both happen to use the same IdP.

For the SaaS / MSP case where a single human really does span tenants, the **identity-link** primitive (Phase 3) lets the parent namespace explicitly declare "entity X in child A and entity Y in child B are the same person, for audit-correlation purposes." The link is one-way visible from the parent, never from siblings.

### Namespace Assignment (Login-Restriction)

> **Status: planned (Phase 5).** Design decisions recorded below; implementation
> tracked in the Phase 5 scope table.

#### Background — how a login picks up a namespace today

Auth *mounts* are **not** namespace-scoped in the current phases. The namespace
router deliberately skips path-rewriting `auth/`, `sys/`, and `identity/`
(`router.rs` — a documented Phase-1 limitation), so a single global
`auth/userpass/users/` table (and one `auth/approle/role/`, `auth/cert/`, …)
backs every namespace. What *is* already namespaced at login time:

- **The token** is bound to the namespace named by the `X-BastionVault-Namespace`
  header at login (`token_binding::resolve_login_namespace` →
  `stamp_binding`), and that binding is enforced on every subsequent request
  (`enforce_request_token_binding`).
- **The entity** is provisioned/loaded in the login namespace — the same
  external principal resolves to a *distinct* entity per namespace
  (`entity_store`, partitioned alias keyspace).
- **Policies** are loaded from the login namespace's keyspace, and identity
  groups are expanded there.

The consequence — and the **gap** this feature closes: a single credential
(`alice` with one password) can authenticate against **any** namespace today.
She simply gets bound to whichever one she names in the header. There is no
notion of "alice belongs to engineering," so isolation depends entirely on every
namespace having no useful policies for unexpected principals — a weak, implicit
guarantee.

#### Design decisions

These were settled explicitly before implementation:

1. **Model: login-restriction, not namespace-scoped auth mounts.** We keep the
   single global auth mount and add an explicit per-principal *assignment list*
   of allowed namespaces, enforced at login. We did **not** adopt full
   Vault-style per-namespace auth mounts (where `alice@engineering` and
   `alice@marketing` are separate credentials with separate passwords); that
   would require lifting the Phase-1 `auth/` rewrite skip and per-namespace auth
   mount tables — a much larger change deferred as possible future work. Under
   the chosen model, the same username is the same person across namespaces;
   assignment only governs *where they may authenticate*.
2. **Scope: all identity types.** Userpass users, AppRoles, and the
   certificate / FIDO2 backends are all covered by the same assignment
   mechanism and the same enforcement helper.
3. **Default: unrestricted (assignment only narrows).** A principal with **no
   assignment record** may log in at any namespace — exactly today's behavior,
   so the change is fully backward-compatible and single-tenant installs are
   unaffected. A **non-empty** record restricts: login is permitted only at a
   listed namespace **or a descendant of one** (reusing
   `token_binding::is_descendant`, so assigning `engineering` also covers
   `engineering/platform`). Enforcement **fails closed** — a record that does
   not permit the target namespace returns `permission_denied`; it never
   silently falls back to root.
4. **Delivery: end-to-end in one initiative** — backend core, enforcement across
   all backends, `v2` management endpoints, and GUI, with tests.

#### Storage

```
sys/identity/ns-assignment/<mount>/<name>   -> { "namespaces": ["engineering", "engineering/platform"] }
```

Keyed by auth mount + principal name (`userpass/alice`, `approle/ci-deploy`,
`cert/<name>`, …). Stored at the **barrier root** (above every per-tenant
prefix, alongside the rest of the global identity keyspace): the record governs
cross-namespace access, so it must be readable from root regardless of the
caller's active namespace. JSON is versioned via `#[serde(default)]` for
forward-compatible field additions. An **empty `namespaces` list is normalized
to no record** (deleting the restriction) so "unrestricted" has a single
representation.

#### Enforcement

A shared helper `ns_assignment::enforce_login_assignment(core, mount, name,
ns_path)` is called in each login handler immediately **after**
`resolve_login_namespace(...)` and before the token is stamped. It loads the
record; if one exists and does not permit `ns_path`, the login fails with
`permission_denied`. The decision core is a pure, unit-testable
`namespace_allowed(allowed, request_ns) -> bool` (empty ⇒ `true`; otherwise
exact-or-descendant match).

Wiring sites: `credential/userpass/path_login.rs`,
`credential/userpass/path_fido2_login.rs`, `credential/approle/path_login.rs`,
the `cert` login path (`credential/cert/`), and standalone
`credential/fido2/path_login.rs`.

#### HTTP surface

Per `agent.md`, new routes ship under `v2/` and are registered in
`configure_sys_routes` (so they are served over HTTP, not only in embedded
vault mode — the same sys-logical-route shimming the namespace CRUD needed):

```
GET    /v2/sys/identity/ns-assignment/<mount>/<name>   # read a principal's allowed namespaces
POST   /v2/sys/identity/ns-assignment/<mount>/<name>   # set the list ({ "namespaces": [...] })
DELETE /v2/sys/identity/ns-assignment/<mount>/<name>   # remove the restriction (back to unrestricted)
LIST   /v2/sys/identity/ns-assignment                  # list principals that have an assignment
```

These are **root-scoped** management endpoints (the assignment is a deployment-
level authorization fact, authored by an operator with the appropriate root
policy), so the GUI commands reach them via `make_request_root`.

#### GUI

The Users page and AppRole page gain a **"Namespaces" multi-select** (options =
`listNamespaces()` + the root entry). An empty selection renders as an
"All namespaces (unrestricted)" state and persists as *no record*. Tauri
commands `get_ns_assignment` / `set_ns_assignment` / `delete_ns_assignment`
drive the `v2/sys/identity/ns-assignment` endpoints.

### Audit Wiring

Audit broadcasters are per-namespace by default. A broadcaster configured in `engineering` does not see traffic from `marketing`. The root namespace has an additional **superuser audit** mode (off by default; explicit opt-in) that mirrors every namespace's audit stream to a root-level broadcaster — used by central SOCs that need a unified view across tenants. When enabled, every namespace shows the mirror in its `LIST /sys/audit` output so tenants are aware their events are being shadowed.

### Quotas

Per-namespace, configured at the parent:

| Quota | Description |
|---|---|
| `max_storage_bytes` | Hard cap on total barrier-encrypted bytes under the namespace prefix. |
| `max_leases` | Hard cap on live leases. |
| `request_rate` | Token-bucket rate limit on API requests, per-namespace. |
| `max_mounts` | Hard cap on mounts inside the namespace. |
| `max_entities` | Hard cap on identity entities. |
| `max_child_namespaces` | Hard cap on child namespaces. |

Quotas are enforced at request-admit time; exceeding any quota fails the request with a clear `429 Too Many Requests` (rate) or `507 Insufficient Storage` (capacity). Quota state is updated lazily via the existing storage broadcasters; a per-namespace daemon reconciles every 60s.

### Module Architecture

```
src/modules/namespace/
├── mod.rs                          -- NamespaceModule; sys path registration
├── store.rs                        -- NamespaceStore: CRUD + path resolution + child/parent indices
├── router.rs                       -- request -> (namespace, mount, path) resolver
├── token_binding.rs                -- token namespace_id check; child_visible logic
├── policy_scope.rs                 -- policy engine integration; cross-namespace path refusal
├── audit_scope.rs                  -- per-namespace broadcaster registration; root mirror
├── quota.rs                        -- quota enforcement + reconciliation
├── identity_link.rs                -- Phase 3 cross-tenant identity linking
└── path_*.rs                       -- /v1/sys/namespaces/* HTTP path handlers
```

The biggest non-`namespace/` change is the **mount router**: today there is one global `MountsRouter`; it becomes one router per namespace, indexed by namespace UUID, with the per-namespace router resolved at request-admit time.

### HTTP Surface

```
LIST   /v1/sys/namespaces                          # list children of caller's namespace
POST   /v1/sys/namespaces/<path>                   # create
GET    /v1/sys/namespaces/<path>                   # read metadata + quotas
PATCH  /v1/sys/namespaces/<path>                   # update (rename, quotas, child_visible default)
DELETE /v1/sys/namespaces/<path>                   # delete (refused unless empty)
POST   /v1/sys/namespaces/<path>/seal              # seal a single namespace (Phase 4 nice-to-have)
POST   /v1/sys/namespaces/<path>/unseal            # symmetric
GET    /v1/sys/namespaces/<path>/quotas
PATCH  /v1/sys/namespaces/<path>/quotas
```

Plus the cross-cutting changes: every existing `/v1/...` endpoint now accepts the `X-BastionVault-Namespace` header / path-prefix form.

## Implementation Scope

### Phase 1 — Namespace Container + Mount Routing

Land the data model and the routing path. No identity/policy/audit scoping yet — those live in the root namespace as today, and child namespaces start out functionally empty.

| File | Purpose | Status |
|---|---|---|
| `src/modules/namespace/mod.rs` | Module registration + tests. | ✅ Done |
| `src/modules/namespace/store.rs` | Namespace CRUD + path↔UUID index + validation + delete guards. | ✅ Done |
| `src/modules/namespace/router.rs` | Header / path-prefix → namespace resolver + prefix helpers. | ✅ Done |
| `src/modules/namespace/mount_registry.rs` | Per-namespace `MountsRouter` registry (reuses router-prefix). | ✅ Done |
| `src/modules/namespace/migrate.rs` | Idempotent non-destructive re-root *copy* + verify. | ✅ Done (copy); activation gated/deferred |
| `src/modules/system/mod.rs` (extension) | `v2/sys/namespaces` CRUD handlers. | ✅ Done |
| `src/core.rs` (extension) | Run migration copy at `post_unseal`. | ✅ Done |
| Per-namespace mount creation + request dispatch (`mount.rs` `mount_one`/`unmount_one`, registry `mount`/`unmount`/`list_mounts`, header→path rewrite in `core.rs`, namespace-aware `sys/mounts`) | A child namespace holds mounts and routes end-to-end; cross-tenant isolation proven. | ✅ Done |
| Re-root *activation* (Core boot-time prefix flip) | Make `namespaces/<root_uuid>/...` authoritative — **the unconditional default for every install** (no opt-in). `Core::post_unseal` resolves activation (`migrate::resolve_root_activation`) before any view/mount-table use and repoints `system_view` + the (now `ArcSwap`) root `mounts_router` + `root_storage_prefix`; `Core::mount` and `exchange/scope` derive the prefix from it. New installs activate immediately; existing installs run the non-destructive copy + verify eagerly the same boot and flip only if it verifies (fail-safe: retry next boot, never block unseal). Persistent one-way marker; legacy keys retained for BVBK rollback. | ✅ Done |

### Phase 2 — Per-Namespace Policy + Token + Audit

| File | Purpose | Status |
|---|---|---|
| `src/modules/namespace/token_binding.rs` | Namespace-bound tokens; `child_visible` flag; enforcement in `Core::handle_request`; create-time binding via header; root bypass. | ✅ Done (explicit token-create binding); per-login binding deferred |
| `{{namespace.path}}` / `{{namespace.id}}` policy templates (`src/modules/policy/policy_store.rs`) | Namespace-aware ACL templating. | ✅ Done |
| `namespace` field on audit entries (`src/audit/entry.rs`) | Per-tenant audit attribution. | ✅ Done |
| `src/modules/namespace/policy_scope.rs` — cross-namespace path refusal (write-time guard, wired into policy write) | Refuses policies referencing another namespace's paths. | ✅ Done |
| Per-namespace policy *storage* (separate policy documents per namespace, `src/modules/policy/policy_store.rs`) | Tenant ACL policies live in their own keyspace (`policy-ns/<b64(path)>/…`); root keeps the legacy keyspace. `get/set/list/delete/history` gain `_ns` variants; the `sys/policy*` handlers scope by the request namespace header. | ✅ Done |
| `src/audit/broker.rs` — per-namespace *broadcasters* + root mirror | Devices carry a `namespace` + root-only `mirror` flag; `log` partitions fan-out by `entry.namespace` with a per-namespace hash chain and a superuser mirror on the root chain; `sys/audit` enable/disable/list scope by header. | ✅ Done |
| `src/modules/policy/policy_store.rs` `new_acl_inner` (extension) | Compiles policies against the calling token's bound namespace (loads each named policy from that namespace's store). | ✅ Done |

### Phase 3 — Per-Namespace Identity + Cross-Tenant Linking

| File | Purpose | Status |
|---|---|---|
| `src/modules/identity/entity_store.rs` (extension) | Per-namespace alias keyspace + `namespace` tag on each entity record (entity UUIDs stay globally unique, so `get_entity(id)` callers are unchanged); `_ns` get/create/forget/list variants. The same external principal resolves to a distinct entity per namespace. | ✅ Done |
| `src/modules/identity/group_store.rs` (extension) | Per-namespace group + group-history keyspaces; `_ns` CRUD + history + `expand_policies_ns` so login-time group→policy expansion is namespace-scoped. | ✅ Done |
| `src/modules/identity/mod.rs` (extension) | Group-management + entity-alias HTTP handlers scope by the `X-BastionVault-Namespace` header; `identity/` is exempted from path-rewrite so it stays header-scoped like `sys/`. | ✅ Done |
| Per-login namespace binding (`credential/userpass`, `credential/approle`) | Login resolves the namespace header (fails closed on an unknown namespace), provisions/loads the entity and expands groups *in that namespace*, and stamps the token's namespace binding. Covers userpass password + userpass-FIDO2 + approle. (`cert` login: follow-up.) | ✅ Done |
| `src/modules/namespace/identity_link.rs` + `v2/sys/namespace-links` | Parent-visible cross-tenant identity correlation: a namespace may link entities only within its own subtree (one-way), stored partitioned by owner so siblings/children never see it. List/create/read/delete via the system backend, scoped by header. | ✅ Done |

### Phase 4 — Quotas + GUI

| File | Purpose | Status |
|---|---|---|
| `src/modules/namespace/quota.rs` | **All six quotas enforced.** Counting/rate: `max_mounts` (at mount create), `max_child_namespaces` (at namespace create), `request_rate` (per-namespace token bucket, `429`). Accounting: `max_entities` (at login before a *new* entity is provisioned), `max_storage_bytes` (summed under the namespace logical prefix, incoming value added so the crossing write is the one refused, `507`), `max_leases` (live lease count under the namespace, enforced at lease registration). All accounting quotas apply to non-root namespaces only. | ✅ Done |
| `gui/src/routes/NamespacesPage.tsx` + `gui/src-tauri/.../commands/namespaces.rs` + `gui/src/lib/api.ts` | Namespace management page: list root children, create (path + 6 quota fields + `child_visible_default`), edit quotas, delete. Tauri commands drive `v2/sys/namespaces`. | ✅ Done |
| `gui/src/components/NamespaceSwitcher.tsx` + `bv_client::Backend::handle_with_namespace` | Top-of-sidebar namespace picker. Selecting a namespace sets the session's active namespace on the backend (`AppState.active_namespace`), and `make_request` carries the `X-BastionVault-Namespace` header on every authenticated request via the new `handle_with_namespace` trait method (overridden by both the embedded and remote backends). Reloads so all pages re-fetch under the tenant. | ✅ Done |
| Tree view + rename in the GUI | The page lists root-level children flat; a recursive tree and rename are follow-ups (namespace rename is not yet implemented server-side either). | ⏳ Deferred |

### Phase 5 — Per-Principal Namespace Assignment (Login-Restriction)

Restrict *which namespaces a credential may authenticate into*. Backward-
compatible: no assignment record ⇒ unrestricted (today's behavior). See the
"Namespace Assignment (Login-Restriction)" design section above for the settled
decisions and rationale.

| File | Purpose | Status |
|---|---|---|
| `src/modules/namespace/ns_assignment.rs` | New module: `NsAssignmentStore` (barrier-root CRUD, empty-list ⇒ delete), pure `namespace_allowed(allowed, request_ns)` decision (empty ⇒ all; exact-or-descendant via `is_descendant`), and `enforce_login_assignment(core, mount, name, ns_path)` (fail-closed `permission_denied`). Unit + store-roundtrip tests. | ✅ Done |
| `src/modules/credential/userpass/path_login.rs`, `…/path_fido2_login.rs`, `src/modules/credential/approle/path_login.rs` | Call `enforce_login_assignment` after `resolve_login_namespace`, before token stamping. Covers userpass password, the GUI's userpass-FIDO2, and approle — the three backends that bind a login namespace today. | ✅ Done |
| `cert` / standalone `fido2/` backends | **Not gated yet, by necessity.** The legacy `cert` auth method is disabled in the OpenSSL-free default build (produces no `Auth`), and the standalone `fido2/` backend is not namespace-aware (it never resolves a login namespace). Assignment enforcement for these is contingent on the separate "`cert`-login namespace binding" follow-up; the assignment **store and endpoints already accept any mount**, so records can be authored ahead of that work. | ⏳ Deferred (prereq: namespace binding) |
| `src/modules/system/mod.rs` + `src/http/sys.rs` | `v2/sys/identity/ns-assignment/<mount>/<name>` Read/Write/Delete + `v2/sys/identity/ns-assignment` List, registered in `configure_sys_routes` so they serve over HTTP (not embedded-only). The mount segment is normalized to the trailing-slash form (`userpass/`) so API-written records match what the login paths key on. | ✅ Done |
| `gui/src-tauri/src/commands/namespaces.rs` + `gui/src/lib/api.ts` | `get/set/delete_ns_assignment` Tauri commands (root-scoped via `make_request_root`) + api wrappers. | ✅ Done |
| `gui/src/routes/UsersPage.tsx` + `gui/src/routes/AppRolePage.tsx` | "Allowed namespaces" multi-select (empty ⇒ unrestricted), shown only when child namespaces exist. Users page edits load/save the current assignment; AppRole page sets it at create. | ✅ Done |

### Not In Scope

- **Namespace-scoped auth mounts.** Phase 5 restricts *where a global credential may authenticate*; it does not give each namespace its own auth mount / user table. Per-namespace credentials (separate `alice` per tenant, separate passwords) would require lifting the Phase-1 `auth/` rewrite skip and are deferred as possible future work.
- **Cross-namespace mount sharing** (one mount visible from two namespaces). Each namespace gets its own mount instance; if two need the same backend, they each mount it. Cross-mount sharing breaks the blast-radius story.
- **Performant introspection across all namespaces** beyond what the audit mirror gives. Listing every secret across every namespace as a single root-level operation is intentionally absent.
- **Hierarchical policy inheritance.** A child namespace does not inherit the parent's policies. Operators replicate policies they want in every child via the catalog (Phase 4 GUI helps).
- **Per-namespace barrier keys.** The barrier remains single-keyed; namespaces are a logical isolation, not a cryptographic one. Customers needing cryptographic per-tenant isolation deploy separate BastionVault instances. (This is the same tradeoff Vault Enterprise makes.)
- **Migration of existing per-user scoping to per-namespace scoping.** Per-user ownership remains a separate, namespace-internal concept; the two compose (a user owns secrets within a namespace).

## Testing Requirements

### Unit Tests

- Namespace path → UUID resolver: every path in a tree round-trips; ambiguous paths refused.
- Token binding: a token issued in `engineering` cannot operate in `marketing`; with `child_visible=true` it can operate in `engineering/platform`; never in `engineering/peer-team`.
- Policy compile-time refusal: a policy with `path "marketing/secret/*"` written from inside `engineering` is rejected at PUT time.
- Quota enforcement: 1001st mount in a `max_mounts=1000` namespace fails with the right error; rate limiter token bucket refills correctly.
- Namespace assignment (`namespace_allowed`): empty list ⇒ every namespace allowed; an exact path match is allowed; a descendant of an assigned path is allowed; a sibling/parent/unrelated namespace is refused.

### Integration Tests

- Create root + two siblings (`tenant-a`, `tenant-b`); mount `secret/` in each; write `foo` in tenant-a; confirm tenant-b's `secret/foo` is `404`. Audit logs show the access only in tenant-a's broadcaster.
- Migration: start with a vault containing existing root-level data, upgrade to namespace-aware build, confirm all data is reachable at the new `namespaces/<root_uuid>/...` prefix and that no client-visible API breaks.
- Child-visible token: parent admin issues a `child_visible=true` token; uses it in `tenant-a`; admin actions succeed; switches header to `tenant-b`, same actions succeed; switches header to `tenant-c` (sibling of issuer), action fails.
- Namespace assignment (login-restriction): assign `userpass/alice → [engineering]`; her login with header `engineering` succeeds and her login with header `marketing` is refused with `permission_denied`; after the assignment is deleted both succeed again; a principal that was never assigned logs in everywhere (unrestricted default). Regression-proves the deny cannot silently regress to the unrestricted path.
- Audit mirror: enable root mirror, write in `tenant-a`, confirm event appears in tenant-a's broadcaster *and* the root broadcaster, with the `namespace` field populated.
- Quota: set `max_storage_bytes=1MiB` on `tenant-a`, write 1.1MiB across many secrets, confirm the write that crosses the threshold fails with `507`; later writes after a delete succeed.

### Cucumber BDD Scenarios

- MSP operator creates `customer-acme` and `customer-globex` namespaces; provisions an admin token in each; the customer-acme admin tries to read a secret in customer-globex and fails with a clear permission error and an audit entry in their own (not globex's) audit log.
- Single-tenant team adopts the feature: existing data continues to live at the root namespace; a new `staging` child namespace is created for non-prod work; staging tokens cannot touch root data.

### Negative Tests

- Creating a namespace with a name containing `/`, `..`, or `*`: rejected.
- Deleting a namespace that has child namespaces or mounts: rejected with a clear listing of what blocks the delete.
- Writing to a namespace path that doesn't exist: 404, not 403 (so the response distinguishes "no such namespace" from "you're not allowed").
- A token issued in `engineering/platform` operates with header `X-BastionVault-Namespace: engineering` (parent): rejected with `permission_denied`, audit-logged in the parent's broadcaster.

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`**: same constraint as every other module. CI must fail if either becomes reachable.
- **Storage-prefix isolation is a barrier-side guarantee.** Every namespace's storage view rewrites to its own prefix; the underlying physical backend never sees an un-prefixed key. A bug that lets a request from one namespace read another's prefix is treated as a security incident, not a regression.
- **Token-binding is enforced before any backend dispatch.** The HTTP layer resolves namespace before policy; a request with the wrong namespace token never reaches the backend.
- **Audit completeness across the boundary.** Every cross-namespace permission failure is logged in the *requestor's* namespace audit (so the requestor's auditor can see attempted escapes); the *target's* audit gets nothing (so a stranger pinging your namespace doesn't pollute your log). The design splits "who tried" and "what was tried" intentionally.
- **Quota DoS protection.** Quota counters are bounded and updated through the same broadcaster path the rest of storage uses; an attacker cannot flood a namespace into exhaustion via a partial-write tactic because each write is admitted only after the counter increment.
- **Migration is idempotent and reversible at the storage level.** The first launch on the new build creates the root-namespace prefix and re-roots existing data; the migration script is checked in and can be replayed if needed. Until Phase 4 ships in production-stable form, customers can roll back to a pre-namespace build by restoring from a pre-migration backup (the BVBK format already supports this).
- **No cryptographic isolation between namespaces.** The barrier is single-keyed; an attacker with full barrier access can read every namespace. Customers needing cryptographic per-tenant isolation must deploy separate BastionVault instances. Documented loud and clear in the user-facing namespaces page.
- **Identity-link is one-way.** A parent namespace can declare two child entities are the same person; child namespaces cannot see the link. This prevents a child operator from enumerating which of their users also exist in sibling namespaces.
- **Namespace assignment fails closed and only narrows.** With no record a credential is unrestricted (preserving single-tenant behavior); with a record, a login at a non-permitted namespace is refused with `permission_denied` — never a silent fallback to root. Because the global auth mount is shared, the assignment is the *only* gate on where a credential may bind; it is therefore a root-authored, deployment-level authorization fact stored above every tenant prefix and not writable from within a tenant. It restricts authentication, not authorization within a namespace — a principal still needs policies in the namespace to do anything once bound.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md) (move from `Partial` → `In Progress` (Phase 1) → `Done` (Phase 4)), and this file's "Current State" / phase markers.
