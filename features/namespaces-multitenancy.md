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
> namespace binding across userpass/FIDO2/approle/ferrogate **and the SSO and
> standalone-security-key mounts (`oidc/`, `saml/`, `fido2/`)** — with `child_visible`
> following the login namespace's `child_visible_default` flag
> (`token_binding::login_child_visible`) rather than a hardcoded `false`, so an
> operator can opt a namespace into minting child-visible admin tokens —
> cross-namespace policy-path refusal
> (`policy_scope.rs`), the cross-tenant identity-link primitive
> (`identity_link.rs`, `v2/sys/namespace-links`), and counting + rate quota
> enforcement (`quota.rs`). Per-namespace **policy storage** lives in
> `src/modules/policy/policy_store.rs` (tenant ACL keyspaces + namespace-aware
> ACL compilation); per-namespace **audit broadcasters** + the root superuser
> mirror live in `crates/bv-audit/src/broker.rs`; per-namespace **identity** (entities,
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
> **Binding-aware capabilities.** `sys/capabilities-self` reports whether the
> calling token may actually *operate* in the active namespace, not just its raw
> policy caps: a token bound elsewhere (without child-visibility) gets empty
> capabilities plus `namespace_operable: false` / `token_namespace` /
> `active_namespace`. The GUI renders a persistent read-only banner
> (`NamespaceGuardBanner`) from that flag, so switching the namespace picker to a
> tenant your token can't operate in explains itself instead of failing with an
> opaque 403 on the first write. The banner also *repairs* it: it names the
> allowed-namespace entry the session's principal lacks and, for a caller who can
> already write `sys/identity/ns-assignment/*`, writes it on one click.
> Operability is resolved per request, so the grant lands on the open session —
> no new token and no re-login. A token that stamps no principal (`mount_path` +
> `username`/`role_name`) reports `known: false` and gets the explanation only,
> because no assignment could be matched to it either.
>
> **In progress (Phase 5):** per-principal **namespace assignment**
> (login-restriction) — restrict which namespaces a credential may authenticate
> into, across all auth backends, unrestricted by default. See the "Namespace
> Assignment (Login-Restriction)" design section and the Phase 5 scope table.
>
> **A restricted principal can now actually sign in.** Fail-closed enforcement on
> its own locked tenant-only credentials out of every client without a namespace
> picker: the GUI login page sends no namespace header, so the login resolved to
> root and was denied — `HTTP 403: Permission denied` on a correct password. An
> **unscoped** login (no header) now binds to the principal's first assigned
> namespace; naming a namespace explicitly still fails closed. The GUI lands the
> session there via the new caller-introspecting
> `GET /v2/sys/namespaces-self`, which also drives the namespace switcher, so it
> only ever offers namespaces the session can operate in and hides itself when
> there is only one. An admin is never left without a picker: a missing or
> single-entry answer falls back to the sudo-gated namespace tree walk
> (`widenWithAdminWalk`), which a tenant principal is 403'd on.
>
> **Namespace self-service.** Every authenticated token bound to a non-root
> namespace now implicitly carries a `namespace-self` ACL policy so it can reach
> the caller-introspecting / self endpoints (`sys/capabilities-self`,
> `auth/token/lookup-self`, token renew/revoke-self, lease + wrapping
> self-service, `identity/entity/self`, `identity/sharing/for-me`,
> `cubbyhole/*`). A child namespace "starts empty" — no `default` policy, none
> inherited from root — so these previously all returned `HTTP 403`; and a
> namespace policy could not re-grant them because `refuse_cross_namespace_paths`
> rejects root-owned `sys/*` / `auth/*` rules. The implicit policy is injected in
> `PolicyStore::new_acl_inner`, never stored/listed/assignable, carries no tenant
> data access, and is added only for non-root bindings (root is unchanged).
> (`policy_store::NAMESPACE_SELF_POLICY`)
>
> **Unresolvable policy names are denied, not 500.** A root-bound token whose
> policy list names a policy that exists only inside a child namespace resolves
> nothing on its `ns_path == ""` path. `get_policy_ns` already skipped such names
> for namespace-bound tokens, but the root path routed through `get_policy` with
> `PolicyType::Token`, which treated a miss in the in-memory `policy_type_map` as
> "no barrier subview" and failed the request with `unable to get the barrier
> subview for policy type token` — so the identical operator slip (auth role at
> the root, policy created in the tenant) was a clean 403 inside a namespace and
> an opaque HTTP 500 at the root. `Token` lookups now read through to the
> replicated ACL (then RGP) keyspace and memoize the resolved type; a name in
> neither resolves to `Ok(None)` so `new_acl_inner` skips it and the request is
> denied on its merits, with a warning logged so a silently-dropped policy is
> visible. The same read-through closes an HA split unrelated to namespaces:
> `policy_type_map` is per-node, built once in `PolicyStore::new` and afterwards
> only by the writes that node served, so a policy written against one Hiqlite
> member replicated its bytes but not its type entry — the same token worked on
> that member and 500'd on its peers until they restarted.
>
> **Remaining follow-ups:**
> - **`cert`-login** namespace binding, and broader **tenant self-service of
>   `sys/*`** beyond the introspection/self endpoints above (e.g. tenant-scoped
>   mount management by a namespace admin, today reachable only by root/sudo
>   tokens carrying the namespace header).
> - A GUI namespace **tree view + rename**. The list now surfaces the full
>   tree (the `list_namespaces` Tauri command walks it breadth-first and returns
>   full slash-delimited paths, so nested namespaces like `dti/esi` appear on
>   the Namespaces page, the switcher, and Users / AppRole scoping), but it is
>   still rendered as a flat list rather than an indented tree, and server-side
>   rename is not yet implemented.
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

A token's `child_visible` value at login is taken from the login namespace's
`child_visible_default` flag (`token_binding::login_child_visible`). The root
namespace's flag is configurable through the self-config route (`GET`/`POST
/v1/sys/namespaces` with no path) — the by-path route cannot address root.

> **Security — root `child_visible_default` is a broad grant, default-off.**
> Because the root namespace is the ancestor of *every* namespace, enabling its
> `child_visible_default` makes every token minted at a root login (e.g. a
> userpass user who authenticates with no `X-BastionVault-Namespace` header)
> child-visible, and therefore able to operate in **every** descendant namespace
> (still gated by each namespace's ACL). This collapses much of the isolation
> multi-tenancy provides, so it is off by default and root/sudo-gated. Prefer
> binding an admin to the specific parent namespace they administer and enabling
> `child_visible_default` there, rather than on root.

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

> **Assignment governs authorization, not only login.** In addition to gating
> *where a credential may authenticate*, an explicit assignment record widens
> *request-time operability*: `token_binding::token_operable_resolved` (used by
> `enforce_request_token_binding` and `sys/capabilities-self`) treats a
> principal **explicitly assigned** a namespace — or an ancestor of it — as
> operable there from **any** session, even a token bound to a different
> (e.g. root) namespace. This lets an admin assigned `dti/esi` read and write it
> without a separate login into that namespace. The widening is deliberately
> **explicit-only**: the login-time "no record ⇒ unrestricted" convenience is
> *not* applied to authorization, so a principal with no assignment keeps the
> strict binding verdict and an absent record can never promote a bound token
> into a cross-tenant superuser. The lookup is live (not a login snapshot), so
> revoking an assignment takes effect on the next request.

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
ns_path)` is called in each login handler immediately **after** the login
namespace is resolved and before the token is stamped. It loads the record; if
one exists and does not permit `ns_path`, the login fails with
`permission_denied`. The decision core is a pure, unit-testable
`namespace_allowed(allowed, request_ns) -> bool` (empty ⇒ `true`; otherwise
exact-or-descendant match).

Wiring sites: `bv-auth-userpass/src/path_login.rs`,
`bv-auth-userpass/src/path_fido2_login.rs`, `bv-auth-approle/src/path_login.rs`,
`bv-auth-ferrogate/src/path_machines.rs`, `bv-auth-oidc/src/path_callback.rs`,
`bv-auth-saml/src/path_callback.rs`, and standalone
`bv-auth-fido2/src/path_login.rs`. The `cert` mount has no login path in the
OpenSSL-free build, so there is nothing to wire.

#### Unscoped login → the principal's default namespace

Fail-closed enforcement alone made a tenant-only credential **unable to
authenticate at all** from any client that has no namespace picker: the GUI login
page, and the CLI without `-namespace`, send no `X-BastionVault-Namespace`
header, so the login resolved to root and then hit the assignment denial —
`HTTP 403: Permission denied` on a correct password.

The fix distinguishes *"give me the default namespace"* from *"give me root"*.
Login handlers call `token_binding::resolve_login_namespace_for_principal(core,
req, mount, name)` instead of `resolve_login_namespace`:

- **Header present** → resolved exactly as before, and the assignment check still
  fails closed. (Root can be named explicitly as `"/"`, which normalizes to the
  root path; an *empty* header value is treated as absent.)
- **No header** → if the principal's assignment excludes root, the login binds to
  its **first assigned namespace** (`ns_assignment::default_login_namespace` —
  the record preserves the operator-authored order, so "first" is the operator's
  own preference). Unrestricted principals, and those assigned root explicitly,
  still land at root.

This cannot widen access: the chosen path always comes from the principal's own
assignment, so `enforce_login_assignment` still holds on it, and the redirection
is logged to the `security` target.

##### Diagnosing a 403 on a tenant login

The explicit-header branch is the only remaining way a correct password 403s, so
the first question is always *which namespace did the login resolve to*. Two
`security`-target log lines answer it outright:

- `login for '<mount><name>' defaulted to assigned namespace "…" (no namespace
  requested; root is not assigned)` — the unscoped redirection fired.
- `login denied: principal '<mount><name>' is not assigned to namespace "…"` —
  the refusal, naming the namespace the login actually bound to. A `""` there on
  an unscoped login means the resolver never redirected, i.e. the server predates
  this fix.

On the Audit page the refusal is a `denied` row carrying
`reason=credential-refused` at the full `auth/<mount>/login/<name>` path.
Earlier builds recorded it as `reason=invalid-token` at the mount-relative
`login/<name>`, which reads as a token problem and points at the wrong
subsystem — see the [CHANGELOG](../CHANGELOG.md) entry "A refused login no longer
blames the token".

#### `sys/namespaces-self` — which namespaces may I use?

The `sys/namespaces` CRUD surface is a **root-protected (sudo)** path, so a
tenant principal has no grant on it and could not discover even the namespace it
had just logged into; a namespace picker built on it either showed nothing or
offered tenants the caller would be 403'd in.

`GET /v2/sys/namespaces-self` is the caller-introspecting counterpart:

```json
{ "namespaces": ["tenant-a", "tenant-a/sub"], "token_namespace": "tenant-a", "root": false }
```

Membership is decided by `token_binding::token_operable_resolved` — the exact
verdict `enforce_request_token_binding` applies per request — so the list can
never advertise reach the caller does not have, while a root or child-visible
token correctly sees the whole subtree. The **root namespace participates as the
empty string**, so `""` appears exactly when the caller may operate at root.
Granted by the built-in `default` and `namespace-self` policies (it is
caller-filtered, so it is safe for every authenticated token).

The GUI uses it for two things: `namespaceStore.landSession()` runs on every
login (and on a restored session after a vault switch) to set the session's
active namespace to `token_namespace` — otherwise a tenant token's first fetch
403s despite a successful sign-in — and the sidebar `NamespaceSwitcher` renders
its options from `namespaces`, hiding itself entirely when there is only one
namespace to choose from.

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
GET    /v1/sys/namespaces                          # read the caller's OWN namespace config (root when unscoped)
POST   /v1/sys/namespaces                          # update the caller's OWN namespace config (quotas + child_visible_default)
POST   /v1/sys/namespaces/<path>                   # create (seeds default engines: secret/, resources/, files/, resource-group/, identity/)
GET    /v1/sys/namespaces/<path>                   # read metadata + quotas
PATCH  /v1/sys/namespaces/<path>                   # update (rename, quotas, child_visible default)
DELETE /v1/sys/namespaces/<path>                   # delete (cascade-unmounts engines + clears their data; refused if it has child namespaces)
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
| `src/modules/namespace/token_binding.rs` | Namespace-bound tokens; `child_visible` flag; enforcement in `Core::handle_request`; create-time binding via header; root bypass; per-login binding across userpass/FIDO2/approle with `child_visible` from the namespace's `child_visible_default`; shared `token_operable` verdict, plus `token_operable_resolved` (assignment-aware widening) reused by both `enforce_request_token_binding` and `sys/capabilities-self`. | ✅ Done |
| `{{namespace.path}}` / `{{namespace.id}}` policy templates (`src/modules/policy/policy_store.rs`) | Namespace-aware ACL templating. | ✅ Done |
| `namespace` field on audit entries (`crates/bv-audit/src/entry.rs`) | Per-tenant audit attribution. | ✅ Done |
| `src/modules/namespace/policy_scope.rs` — cross-namespace path refusal (write-time guard, wired into policy write) | Refuses policies referencing another namespace's paths. | ✅ Done |
| Per-namespace policy *storage* (separate policy documents per namespace, `src/modules/policy/policy_store.rs`) | Tenant ACL policies live in their own keyspace (`policy-ns/<b64(path)>/…`); root keeps the legacy keyspace. `get/set/list/delete/history` gain `_ns` variants; the `sys/policy*` handlers scope by the request namespace header. | ✅ Done |
| `crates/bv-audit/src/broker.rs` — per-namespace *broadcasters* + root mirror | Devices carry a `namespace` + root-only `mirror` flag; `log` partitions fan-out by `entry.namespace` with a per-namespace hash chain and a superuser mirror on the root chain; `sys/audit` enable/disable/list scope by header. | ✅ Done |
| `src/modules/policy/policy_store.rs` `new_acl_inner` (extension) | Compiles policies against the calling token's bound namespace (loads each named policy from that namespace's store). | ✅ Done |

### Phase 3 — Per-Namespace Identity + Cross-Tenant Linking

| File | Purpose | Status |
|---|---|---|
| `src/modules/identity/entity_store.rs` (extension) | Per-namespace alias keyspace + `namespace` tag on each entity record (entity UUIDs stay globally unique, so `get_entity(id)` callers are unchanged); `_ns` get/create/forget/list variants. The same external principal resolves to a distinct entity per namespace. | ✅ Done |
| `src/modules/identity/group_store.rs` (extension) | Per-namespace group + group-history keyspaces; `_ns` CRUD + history + `expand_policies_ns` so login-time group→policy expansion is namespace-scoped. | ✅ Done |
| `src/modules/identity/mod.rs` (extension) | Group-management + entity-alias HTTP handlers scope by the `X-BastionVault-Namespace` header; `identity/` is exempted from path-rewrite so it stays header-scoped like `sys/`. | ✅ Done |
| Per-login namespace binding (`credential/userpass`, `credential/approle`, `oidc`, `saml`, standalone `fido2`) | Login resolves the namespace header (fails closed on an unknown namespace), provisions/loads the entity and expands groups *in that namespace*, and stamps the token's namespace binding. Covers userpass password + userpass-FIDO2 + approle + ferrogate, and now `oidc/`, `saml/` and the standalone `fido2/` mount. (`cert` login: no login path exists.) | ✅ Done |
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
| `src/modules/credential/userpass/path_login.rs`, `…/path_fido2_login.rs`, `src/modules/credential/approle/path_login.rs` | Resolve the login namespace via `resolve_login_namespace_for_principal` (header, else the principal's first assigned namespace), then call `enforce_login_assignment` before token stamping. Covers userpass password, the GUI's userpass-FIDO2, and approle — the three backends that bind a login namespace today. | ✅ Done |
| `src/modules/namespace/ns_assignment.rs::default_login_namespace` + `token_binding::resolve_login_namespace_for_principal` | **Unscoped login lands in the principal's namespace.** A client that names no namespace (GUI login page, CLI without `-namespace`) asked for the *default*, not for root — so a principal whose assignment excludes root binds to its first assigned namespace instead of being denied. An explicitly named namespace (incl. `"/"` = root) still fails closed. Cannot widen access: the chosen path comes from the principal's own assignment. | ✅ Done |
| `src/modules/system/mod.rs::handle_namespaces_self` + `src/http/sys.rs` + `policy_store.rs` | **`GET /v2/sys/namespaces-self`** — the namespaces the *calling token* may operate in (`token_operable_resolved`-filtered, root as `""`) plus its `token_namespace`. Granted by `default` + `namespace-self`, since the `sys/namespaces` CRUD surface is sudo-gated and left a tenant principal unable to discover its own namespace. | ✅ Done |
| `gui/src/stores/namespaceStore.ts` (`landSession`) + `gui/src/routes/LoginPage.tsx` + `gui/src/stores/authStore.ts` | Every login (and a session restored after a vault switch) lands on `token_namespace`, so a tenant token's first fetch carries the matching namespace header instead of 403ing at root. Falls back to root when discovery is unavailable. | ✅ Done |
| `gui/src/components/NamespaceSwitcher.tsx` | Options come from `namespaces-self`, so the picker only offers namespaces the session can actually operate in (root included only when reachable) and hides itself when there is just one. | ✅ Done |
| `gui/src/stores/namespaceStore.ts::widenWithAdminWalk` | **Admin fallback, so the picker cannot go dark.** `namespaces-self` is silent in two operator-visible cases: a server without the route (404 ⇒ empty list for the whole session), and a root-bound, non-child-visible token with no assignment record — operable only at root, so the answer collapses to one entry and the switcher hides itself even for an admin who lists `dti` / `dti/esi` on the Namespaces and Users pages. A missing or single-entry answer now unions in the `sys/namespaces` tree walk. Cannot widen a tenant: that walk is sudo-gated (403 ⇒ the list stays exactly what the token reported), and browsing a non-operable namespace still shows the `NamespaceGuardBanner` read-only strip. | ✅ Done |
| `crates/bv-auth-oidc/src/path_callback.rs`, `crates/bv-auth-saml/src/path_callback.rs`, `crates/bv-auth-fido2/src/path_login.rs` | Same three steps as userpass: resolve the login namespace (an IdP redirect / ACS POST carries no namespace header, so this lands on the principal's first assigned namespace when one is recorded), `enforce_login_assignment`, then stamp `mount_path` + the binding with `child_visible` from the namespace's `child_visible_default`. Before this all three minted a token with **no binding and no `mount_path`**, which read back as root-bound *and* could not be matched to an assignment — so an SSO principal granted several namespaces could operate in none of them, and re-authenticating did not help. SAML keys the principal on the role's mapped `username` when it has one, else the NameID. | ✅ Done |
| `cert` backend | **Not gated, by necessity.** The legacy `cert` auth method is disabled in the OpenSSL-free default build and has no login path at all (produces no `Auth`), so there is nothing to bind or enforce. Contingent on the separate "`cert`-login namespace binding" follow-up; the assignment **store and endpoints already accept any mount**, so records can be authored ahead of that work. | ⏳ Deferred (prereq: a cert login path) |
| `src/modules/system/mod.rs` + `src/http/sys.rs` | `v2/sys/identity/ns-assignment/<mount>/<name>` Read/Write/Delete + `v2/sys/identity/ns-assignment` List, registered in `configure_sys_routes` so they serve over HTTP (not embedded-only). The mount segment is normalized to the trailing-slash form (`userpass/`) so API-written records match what the login paths key on. | ✅ Done |
| `gui/src-tauri/src/commands/namespaces.rs` + `gui/src/lib/api.ts` | `get/set/delete_ns_assignment` Tauri commands (root-scoped via `make_request_root`) + api wrappers. | ✅ Done |
| `gui/src-tauri/src/commands/auth.rs::session_principal` + `gui/src/components/NamespaceGuardBanner.tsx` | **Diagnose and repair, instead of "sign in again".** The banner reads the session's `(mount, name)` off `auth/token/lookup-self`, names the allowed-namespace entry that principal lacks, and offers a one-click grant that appends the active namespace to the principal's existing assignment. The write is the same root/sudo-gated route the Users page uses, so it creates no authority the caller did not already hold, and operability is resolved per request — the grant lands on the open session with no new token. A token that stamps no principal reports `known: false` and gets the explanation only, which is exactly the case where no assignment could be matched to it. | ✅ Done |
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
- Unscoped login + self-discovery: with `userpass/alice → [tenant-a]`, a login that sends **no** namespace header binds the token to `tenant-a` (not root, not a denial), while a login naming root explicitly (`"/"`) is still refused. `GET /v2/sys/namespaces-self` with her token returns `["tenant-a", "tenant-a/sub"]` and `token_namespace: "tenant-a"` — never root, never a sibling — while root's own token sees `["", "tenant-a", "tenant-a/sub", "tenant-b"]`. Driven both logically (`modules::namespace::tests`) and over the real HTTP pipeline (`http::sys::namespace_route_tests`).
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
