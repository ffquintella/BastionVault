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

| File | Purpose |
|---|---|
| `src/modules/namespace/mod.rs` | Module + route registration. |
| `src/modules/namespace/store.rs` | Namespace CRUD + path↔UUID index. |
| `src/modules/namespace/router.rs` | Header / path-prefix → namespace resolver. |
| `src/mount.rs` (extension) | Namespace-aware `MountsRouter`. |
| `src/storage/barrier_*.rs` (extension) | Migrate root prefix into `namespaces/<root_uuid>/...`. |

### Phase 2 — Per-Namespace Policy + Token + Audit

| File | Purpose |
|---|---|
| `src/modules/namespace/token_binding.rs` | Namespace-bound tokens; `child_visible` flag. |
| `src/modules/namespace/policy_scope.rs` | Policy storage scoping; cross-namespace path refusal. |
| `src/modules/namespace/audit_scope.rs` | Per-namespace broadcaster registration. |
| `src/modules/policy/*` (extension) | Compile policies against the calling namespace. |
| `src/modules/audit/*` (extension) | Honour `namespace_id` on broadcaster lookups. |

### Phase 3 — Per-Namespace Identity + Cross-Tenant Linking

| File | Purpose |
|---|---|
| `src/modules/identity/*` (extension) | Per-namespace entity / alias / group stores. |
| `src/modules/namespace/identity_link.rs` | Parent-visible cross-tenant identity correlation. |

### Phase 4 — Quotas + GUI

| File | Purpose |
|---|---|
| `src/modules/namespace/quota.rs` | Storage / lease / rate / mount / entity / child quotas. |
| `gui/src/routes/NamespacesPage.tsx` | Tree view with create / rename / delete / quota editing. |
| `gui/src/components/NamespaceSwitcher.tsx` | Top-bar namespace picker; persists in localStorage. |
| `gui/src/lib/api.ts` (extension) | All API calls accept an optional namespace param that becomes the `X-BastionVault-Namespace` header. |

### Not In Scope

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

### Integration Tests

- Create root + two siblings (`tenant-a`, `tenant-b`); mount `secret/` in each; write `foo` in tenant-a; confirm tenant-b's `secret/foo` is `404`. Audit logs show the access only in tenant-a's broadcaster.
- Migration: start with a vault containing existing root-level data, upgrade to namespace-aware build, confirm all data is reachable at the new `namespaces/<root_uuid>/...` prefix and that no client-visible API breaks.
- Child-visible token: parent admin issues a `child_visible=true` token; uses it in `tenant-a`; admin actions succeed; switches header to `tenant-b`, same actions succeed; switches header to `tenant-c` (sibling of issuer), action fails.
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

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md) (move from `Partial` → `In Progress` (Phase 1) → `Done` (Phase 4)), and this file's "Current State" / phase markers.
