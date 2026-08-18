# Per-User Scoping (Ownership & Sharing)

Status: **All ten phases shipped** — the two baseline roles
(`standard-user-readonly`, `secret-author`) are live; policy templating
(`{{username}}`, `{{entity.id}}`, `{{auth.mount}}`) is wired in at
ACL compile time with fail-closed unresolved-placeholder semantics;
the `shared` ACL scope is wired end-to-end against the `ShareStore`;
admin ownership-transfer endpoints exist at
`POST /v2/sys/{kv,resource}-owner/transfer`; the GUI surfaces a
`/sharing` page (Shared with me + Manage target tabs) plus a
per-resource Sharing tab that shows owner info, an active-share
table with Revoke, a Grant-access modal (also reachable from a Share
button in the resource detail header), and an admin-only
Transfer-ownership modal. On an *unowned* resource that modal is
labelled "Assign owner" and is joined by a "Claim ownership" action —
an admin-only transfer-to-self, since there is no
`sys/resource-owner/claim` endpoint the way there is for KV.
Share re-sharing (a sharee creating further
shares) is intentionally not supported; doing so requires the caller
to own the target or hold an admin capability.

## Goal

Let operators grant narrowly-scoped access to end users based on
*ownership* rather than coarse path prefixes. Two concrete baseline
roles must be expressible:

1. **Read-only user** — can read (and list) secrets and resources they
   own, plus anything explicitly shared with them. Cannot create, update,
   or delete.
2. **Secret author** — can create, read, update, delete, and (future)
   share secrets and resources *they created*, plus anything explicitly
   shared with them. Cannot touch items owned by other users unless they
   have been granted explicit access. The name matches the ownership
   model: you manage what you authored.

Neither role may read or modify a secret or resource owned by another
user without an explicit share. Neither role can manage policies, users,
mounts, or the identity backend.

## Why this is a new feature

Today, ACL policy paths are static strings. A policy like

```hcl
path "secret/data/*" { capabilities = ["read"] }
```

grants read on the entire `secret/` namespace, regardless of who wrote
the entry. BastionVault has no notion of "the caller owns this entry"
when an authorization decision is made. Three things are missing:

1. **Policy templating** — no substitution of caller identity into
   policy paths, so we cannot write `secret/data/users/{{username}}/*`.
2. **Ownership metadata** — KV secrets carry no "owner" field; resources
   carry a free-text `owner` string that is *metadata only* and does not
   participate in authorization.
3. **Share model** — no way to say "alice also gets read on
   `secret/data/users/bob/db-credentials`".

This feature adds all three, minimally.

## Design

### 1. Policy templating

Extend the policy evaluator to substitute a small set of identity
placeholders when an ACL is compiled for a token. Substitution happens
once at token-bind time (or at each request if the token is root-like /
long-lived and metadata changes), producing a concrete path list per
policy instance.

Supported placeholders (v1):

| Placeholder               | Value                                  |
|---------------------------|----------------------------------------|
| `{{username}}`            | `auth.metadata.username`, falls back to `auth.display_name` |
| `{{entity.id}}`            | stable per-user UUID (see §4)         |
| `{{auth.mount}}`          | e.g. `userpass/`, `approle/`           |
| `{{namespace.path}}`      | the namespace the *token is bound to* (root = `""`) |
| `{{namespace.id}}`        | that namespace's UUID (fail-closed when absent) |
| `{{request.namespace}}`   | the namespace the *request* is addressed to (root = `""`, separator swallowed); fail-closed outside the request pipeline |

Rules:

- Templating is opt-in per policy via a `templated = true` hint already
  present on `PolicyEntry` (unused today). A non-templated policy keeps
  its current literal-string semantics.
- Substitution is strict: an unresolved placeholder (e.g., `{{username}}`
  on a root-token request that has no username) fails the
  whole-policy compile with a logged warning and the policy is dropped
  from that token's ACL. This is safer than silently expanding to an
  empty string.
- Only path strings are templated — not capability lists, parameter
  constraints, or other policy fields.

### 2. Ownership metadata

Add an `owner_entity_id` field alongside existing data on every
ownership-aware resource. The field is set on create and never mutated
except by an explicit administrative transfer operation (future).

#### KV secrets (v1 and v2)

Store owner metadata in a parallel sub-view so existing KV payload
layouts are not changed:

```
sys/kv-owner/<mount>/<path>   -> { owner_entity_id, created_at }
```

On `write_secret`, if no entry exists at this key, record the caller as
the owner. On `delete_secret`, remove the owner entry. Reads do not
touch the owner view.

#### Resources

Resources already have an `owner` free-text field. Add a sibling
`owner_entity_id` field (immutable after create) to the `ResourceMetadata`
struct. The old free-text `owner` stays as a descriptive display field;
the new `owner_entity_id` is the authorization key.

### 3. Authorization extension

Introduce an ACL capability qualifier called **scopes**. A policy path
can declare:

```hcl
path "secret/data/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
    scopes       = ["owner"]            # only caller-owned entries
}
```

Supported scope values:

| Scope       | Meaning                                                    |
|-------------|------------------------------------------------------------|
| `owner`     | Grant applies only when `owner_entity_id == caller.entity_id` for the target secret/resource. |
| `shared`    | Grant applies when a `SecretShare` exists for (target, caller). |
| `any`       | Default. No ownership check. Equivalent to omitting `scopes`. |

`scopes` are additive per path: `scopes = ["owner", "shared"]` grants
access when the caller owns the object *or* has an explicit share on
it. For list operations, `owner` scope causes the backend to filter the
listing to caller-owned (or shared) entries rather than rejecting the
call outright.

Authorization check flow (per request):

1. Resolve the full ACL from the caller's policies (with templating
   applied).
2. Match the request path against each rule as today, gathering the
   effective capability set.
3. If any matching rule carries a non-default `scopes` constraint, fetch
   the target's `owner_entity_id` and any `SecretShare` rows for
   `(target, caller.entity_id)` and filter the capability set.
4. Apply the filtered set. For list operations, also filter the response
   keys by ownership/share.

### 4. Identity: caller.entity_id

Per-user scoping needs a stable identifier that survives token churn.
Add a light-weight `EntityStore` under the identity module:

```
Entity {
    id:         UUID (generated on first login),
    primary:    (mount, principal_name),
    aliases:    Vec<(mount, principal_name)>,   // future: cross-mount linking
    created_at: RFC3339,
}

sys/identity/entity/<uuid>            -> Entity
sys/identity/alias/<mount>/<name>     -> uuid   (lookup index)
```

On successful login, the auth backend resolves the alias to an entity
and writes `auth.entity_id` into the issued token's metadata. Templating
and scope checks consume that value.

The initial cut is one-entity-per-(mount, principal); cross-mount alias
merging is a follow-up.

### 5. Sharing

Shipped. The on-disk schema is `SecretShare`:

```
SecretShare {
    target_kind:         "kv-secret" | "resource" | "asset-group" | "file",
    target_path:         "secret/foo/bar" | "server-01" | ...,
    grantee_kind:        "entity" | "group_user" | "group_app",  // default "entity"
    grantee_entity_id:   entity_id | group_name,
    granted_by_entity_id: entity_id,
    capabilities:        Vec<String>,    // subset of read, list, update, delete, create, connect
    granted_at:          RFC3339,
    expires_at:          String,         // RFC3339; "" when no expiry
}

# All under the system barrier view, owned by ShareStore:
sys/sharing/primary/<target_hash>/<grantee>      -> SecretShare
sys/sharing/by-grantee/<grantee>/<target_hash>   -> { target_kind, target_path, grantee_kind }   (entity)
sys/sharing/by-grantee/g:user:<group>/<hash>     -> { ... }                                      (user group)
sys/sharing/by-grantee/g:app:<group>/<hash>      -> { ... }                                      (app group)
sys/sharing/history/<20-nanos>                   -> ShareHistoryEntry                            (append-only audit trail)
```

Each request `Operation` maps to one of those capability names, and a
`scopes = ["shared"]` rule grants its capabilities only when the share carries
the mapped one (`operation_share_capability`, `src/modules/policy/acl.rs`).
`connect` is the exception: it authorizes opening a session against a
resource's credential and has no `Operation` of its own, so the connect gates
probe it with `Request::share_capability_override` (see
`features/connect-only-access.md`). It is deliberately **not** implied by
`read` on a share — a grantee who may see a credential has not thereby been
granted sessions as it, and the reverse pairing (`connect` without `read`) is
the one this makes possible.

Group grantees are *visibility-only*: the share row surfaces the
target on each group member's "Shared with me" feed when (and only
when) the caller carries at least one policy whose
`metadata.group_shared_resources` is `"true"`. ACL capability comes
from regular policies — see `features/identity-groups.md` §Phase 7
for the full design and a sample HCL setup.

Caller-introspection endpoint: `identity/sharing/for-me`. Returns the
union of direct entity shares + group shares the caller is entitled
to, plus a `group_shared_resources` boolean so the GUI can render a
hint when the policy meta tag is missing.

Decisions:
- A sharee cannot re-share — share creation is gated on the target's
  owner / sudo-equivalent policies.
- `delete` propagates: `cascade_delete_target` clears every share on a
  target when the target itself is deleted, including group shares.
- GUI flow: per-target Sharing tab on Resources / KV pages, plus a
  per-user `/sharing` route with `Shared with me` and `Manage target`
  tabs (`gui/src/routes/SharingPage.tsx`).

### 6. Baseline seeded policies

Replace the current `standard-user` seeded policy with two seeded
policies that exercise the new scope machinery:

```hcl
# standard-user-readonly
path "secret/data/*" {
    capabilities = ["read", "list"]
    scopes       = ["owner", "shared"]
}
path "secret/metadata/*" {
    capabilities = ["read", "list"]
    scopes       = ["owner", "shared"]
}
path "resources/*" {
    capabilities = ["read", "list"]
    scopes       = ["owner", "shared"]
}

# plus token self-service + cubbyhole (same as current default)
```

```hcl
# secret-author
path "secret/data/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
    scopes       = ["owner", "shared"]
}
path "secret/metadata/*" {
    capabilities = ["read", "list", "delete"]
    scopes       = ["owner", "shared"]
}
path "resources/*" {
    capabilities = ["create", "read", "update", "delete", "list"]
    scopes       = ["owner", "shared"]
}

# plus token self-service + cubbyhole
```

The existing `standard-user` policy stays as an untemplated, broadly-
scoped compatibility policy for deployments that have not opted into
ownership-aware ACLs. `load_default_acl_policy` seeds all three but
does not force a migration on existing policies.

### 7. API surface

Identity-mount routes work under either `/v1/identity/...` or
`/v2/identity/...`; both prefixes resolve to the same logical backend.
The canonical form used elsewhere is `/v2/identity/...`. System routes
(transfer-of-ownership) live under `/v2/sys/...`.

Ownership / sharing endpoints introduced by this feature:

| Method | Path                                                   | Purpose |
|--------|--------------------------------------------------------|---------|
| GET    | `/v2/sys/identity/entity/self`                         | Read the caller's own entity record |
| GET    | `/v2/sys/identity/entity/{id}`                         | Read an entity (privileged) |
| POST   | `/v2/sys/kv-owner/transfer`                            | Admin-only ownership transfer for a KV entry |
| POST   | `/v2/sys/kv-owner/claim`                               | Caller stamps own entity_id as owner of an unowned KV path. Returns 409 if already owned (use transfer). |
| POST   | `/v2/sys/resource-owner/transfer`                      | Same for a resource |
| PUT    | `/v2/identity/sharing/by-target/{kind}/{b64}/{grantee}` | Create or update a share. Body carries `grantee_kind` (entity / group_user / group_app), `capabilities`, optional `expires_at`. |
| GET    | `/v2/identity/sharing/by-grantee/{grantee}`             | List what is shared *with* an entity (legacy entity-only). |
| LIST   | `/v2/identity/sharing/for-me`                           | Caller-introspecting: direct entity shares ∪ group shares (gated by the `group_shared_resources` policy meta tag). |
| DELETE | `/v2/identity/sharing/by-target/{kind}/{b64}/{grantee}` | Revoke a share. Optional body `grantee_kind` selects which by-grantee pointer prefix to clear. |

All existing `v1/` routes keep working unchanged. When an `owner`- or
`shared`-scoped policy rules a `v1/` path, authorization consults the
owner/share stores the same way.

## Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | `EntityStore`, auto-provision on first login, `auth.metadata["entity_id"]` plumbed into issued tokens | Done |
| 2 | Policy templating (`{{username}}`, `{{entity.id}}`, `{{auth.mount}}`), `templated = true` honored | Done |
| 3 | `scopes` qualifier in ACL grammar + evaluator; `any` scope backward-compatible | Done |
| 4 | KV-secret owner store + write/delete hooks; list-filtering for `owner` scope | Done |
| 5 | Resource owner record + write/delete hooks; list-filtering | Done |
| 6 | Seeded `standard-user-readonly` and `secret-author` policies | Done |
| 7 | GUI: owner info on resource detail; Sharing tab; /sharing page with Shared-with-me + Manage-target tabs | Done |
| 8 | Sharing MVP: `SecretShare` store + v2 API + evaluator hook | Done |
| 9 | Sharing GUI: share dialog, "shared with me" section, revoke flow | Done |
| 10 | Admin ownership-transfer endpoints + GUI | Done |
| 11 | Self-service `kv-owner/claim` endpoint + Claim button + owner-badge in secrets list | Done |

Phases 1–6 deliver the two baseline roles the operator asked for
(`standard-user-readonly` and `secret-author`).
Phases 8–9 deliver sharing. Phase 10 is a small ergonomic follow-up.

## Testing Plan

- **Unit**: templating substitution (missing placeholder drops policy),
  scope filter matrix (`owner`/`shared`/`any` × create/read/update/
  delete/list × owner-match / no-owner / share-match / no-share).
- **Integration**: two users A and B, A writes a secret, B tries to
  read it → denied. A shares it with B → allowed. A deletes → B's
  subsequent read 404s and the share is gone.
- **Regression**: existing `v1/` handler behavior is unchanged when no
  templated or scoped policy is assigned to the caller. All existing
  tests must pass without modification.
- **Migration**: on first unseal after upgrade, KV secrets with no
  owner entry behave as "owned by nobody" → only `any`-scoped policies
  grant access. Document this in the upgrade notes; add a one-shot
  `sys/kv-owner/backfill` maintenance endpoint that assigns a
  configurable `legacy_owner` entity id to all unowned keys.

## Open Questions

- **Multiple entity aliases across mounts.** If alice@userpass/ and
  alice@oidc/ should be the same entity, the EntityStore needs a merge
  operation. Out of scope for phase 1; revisit before phase 8.
- **Root-token behavior.** Does root bypass ownership checks? Proposed:
  yes, because root bypasses ACLs entirely today. Document it.
- **Templated root paths.** `root_paths` (in the system backend) are
  still literal. Templating is policy-evaluation-only.
- **Performance.** Owner lookups happen on every authorize call for a
  scoped path. Need an LRU cache keyed by `(target_kind, target_path)`
  with invalidation on owner writes. Sized conservatively; measure.
- **List filtering order.** If a policy grants `list` with
  `scopes=["owner"]`, the backend must filter *after* the storage list
  call. Large lists could become expensive. A reverse index
  `sys/kv-owner-by-entity/<uuid>/<hash>` is probably required for
  phase 4+.

## Current State

All ten phases are shipped. The two baseline roles
(`standard-user-readonly`, `secret-author`) are seeded alongside the
legacy broadly-scoped `standard-user` policy — `load_default_acl_policy`
installs all three so operators can opt into ownership-aware ACLs
without forcing a migration. Policy templating (Phase 2), the owner
backfill admin endpoint (migration story from the *Testing Plan*), and
the GUI for sharing + owner transfer are all live.

### Using a share from outside the namespace it lives in

A share is stored globally — `ShareStore` keys on the namespace-scoped
canonical target (`dti/esi/segdc1vhm0003`), not in a per-namespace
keyspace — so the "Shared with me" feed lists it for the grantee no matter
where they logged in. Actually *opening* it is a separate question, and until
`shared-access` landed the answer depended on how the grantee reached the
namespace:

| Grantee reaches the namespace by | Implicit policy | Result |
|---|---|---|
| logging in to it (token binding) | `namespace-shared`, templated on `{{namespace.path}}` | share works |
| logging in at root + a cross-namespace assignment | none — injection keys on the *binding* | every open 403s |

The second row is the route the GUI's namespace picker takes for an operator
who authenticates at root. Their request path is rewritten to
`<ns>/resources/...` by `rewrite_request_for_namespace`, while their ACL is
compiled from `default`, whose share-scoped rules are written un-prefixed and
so match nothing.

`shared-access` (seeded, assignable, force-loaded) closes it. Every object
rule is `scopes = ["shared"]` and templated on the new
`{{request.namespace}}` placeholder — the namespace the *request* names,
rather than the one the token is bound to — so one rule text covers root and
any namespace at any depth. It is a named policy an operator attaches per
principal, not a widening of the implicit injection: crossing a tenant
boundary with a share is a decision worth recording in the policy store.

Two properties keep it narrow. It grants nothing without an active
`SecretShare` for the (target, caller) pair carrying the capability the
operation maps to, and it does not confer the right to enter the namespace at
all — `token_operable_resolved` gates that independently, off the namespace
assignment.

### The alias directory across namespaces

`identity/entity/aliases` is what the GUI's grantee picker reads to turn a
login into an `entity_id`. Its keyspace is partitioned per namespace —
`identity-ns/<b64url(ns)>/alias/<mount>/<name>` — because the same external
principal is a *different* entity in each namespace, and a namespace's
partition only fills from logins that carried that namespace's header.

Aliases otherwise live at root: `write_user` pre-provisions there so a
freshly-created user is grantable before their first login, and operators who
authenticate at root keep their root entity while switching namespaces in the
GUI. A strictly namespace-scoped listing was therefore empty for them, which
made sharing impossible outside root without pasting a raw UUID.

A listing made from a namespace now returns that namespace's aliases **plus
root's**; siblings stay isolated. Root is the parent of every namespace and
owns the auth mounts a namespaced caller authenticates through, so nothing is
disclosed that the caller could not enumerate from those mounts. Each record
carries the `namespace` it came from and the two sets are concatenated, never
merged: when a login exists in both, both `entity_id`s are shown, because only
the one the grantee's token actually carries will match at access-check time.

### Per-object filtering of set-returning endpoints

The design's step 4 ("for list operations, also filter the response keys by
ownership/share") is implemented by `PolicyStore::post_route` for `LIST`, via
`list_filter_scopes` / `list_filter_groups` stashed on the request by
`post_auth`. That covers `LIST`, and only `LIST`.

An endpoint that returns a *set* of objects under a different operation is not
covered by it — `resources/resources/search` is an `Operation::Write` returning
an `items` array, so neither the pre-route check (which authorizes the endpoint
path, not the objects) nor the post-route key filter applied to it. It returned
every resource's card projection to any caller who could search.

Such endpoints now filter through **`PolicyStore::readable_targets`**, which
answers "which of these target paths may this caller read?" by re-running
`ACL::allow_operation` against a synthesized per-object request carrying the
same three qualifier inputs `post_auth` resolves for a direct read
(`asset_groups`, `asset_owner`, `target_shared_caps`). Notes for anyone adding
another such endpoint:

- **Do not build this on `ACL::explain_capability`.** That probes with an
  identity-less dry-run request precisely so scope-gated rules contribute
  nothing — correct for "does an explicit ungated grant exist?" (the
  connect-only gate in the Rustion module wants exactly that), but here it
  would hide every object the caller reaches through ownership or a share,
  which is the access a filtered list exists to reveal.
- **Paths must be full, not mount-relative.** A backend handler receives
  `resources/search`; the ACL speaks `resources/resources/search`, and
  `<ns>/resources/resources/…` inside a namespace. `readable_targets` takes
  whatever it is given, so the caller rebuilds the prefix
  (`RESOURCE_METADATA_PATH_PREFIX` plus the namespace).
- **Qualifiers only ever gate.** `readable_targets` exploits this: it evaluates
  once with the qualifiers empty and treats an allow as conclusive, so a caller
  with an ungated grant (and root) costs no extra reads.
- **`req.auth == None` is not filtered** — that is the in-process
  server-authority path, the same convention the credential resolvers rely on.

### Implementation notes (deviations from the design doc)

- **Unified OwnerStore rather than two parallel stores.** The design
  called for `sys/kv-owner/<mount>/<path>` and a
  `ResourceMetadata.owner_entity_id` field. In the ship both KV and
  resource owners live in a single `OwnerStore`
  (`src/modules/identity/owner_store.rs`) under
  `sys/owner/kv/<b64url(canonical-path)>` and
  `sys/owner/resource/<name>`. Keeps the resource payload layout
  stable (no breaking change to `ResourceMetadata`) and gives KV the
  same canonicalization as the resource-group store so a secret's
  owner and group membership key on the same identity.
- **First-write carve-out for the `owner` scope.** A strict "target's
  owner must equal caller" check would make it impossible to create a
  new object under an owner-only policy (no owner exists yet). The
  evaluator therefore treats an unowned target + `Operation::Write` as
  passing the owner scope; `PolicyStore::post_route` then records the
  caller as the owner of the new object. Read / Delete / List /
  Update on an unowned target are still denied, so a legacy secret
  predating this feature is invisible to scoped policies until an
  admin uses a future backfill endpoint to assign ownership.
- **Entity-id lookup via `auth.metadata["entity_id"]`.** The design
  suggested a new `auth.entity_id` field; the ship reuses the
  existing `metadata` `HashMap<String,String>` so no `Auth` struct
  change was needed. UserPass, AppRole, and FIDO2 login handlers
  resolve an entity via `EntityStore::get_or_create_entity(mount,
  name)` and insert the resulting UUID into metadata.
- **Policy templating is live.** `apply_templates` in
  `src/modules/policy/policy_store.rs` substitutes `{{username}}`,
  `{{entity.id}}`, and `{{auth.mount}}` (plus their
  `identity.entity.*` aliases) in every path of a `templated`
  policy at request time, using the caller's `Auth`. Unresolved
  placeholders (missing metadata, unknown placeholder name) drop the
  affected path rule fail-closed; a policy whose every rule drops
  returns `None` so the caller gets no authorization from it. The
  parser also auto-detects `{{…}}` syntax in paths and flips
  `templated = true` so operators do not need to set the flag
  explicitly. Nine unit tests in `policy_store::templating_tests`
  cover happy path, fail-closed on typos / missing values, rule-level
  drop vs. whole-policy drop, display_name fallback for
  `{{username}}`, and preservation of capabilities / scopes through
  the substitution.
- **Owner backfill endpoint**
  (`POST /v2/sys/owner/backfill`, sudo-gated via `root_paths`):
  one-shot admin tool for deployments that ran before per-user-scoping
  landed. Accepts `{ entity_id, resources?, kv_paths?, dry_run? }`
  and stamps the given `entity_id` as owner on every currently
  *unowned* target in the request. Already-owned objects are
  skipped (use the `*-owner/transfer` endpoints to overwrite). The
  response reports per-kind counts (`stamped` / `already_owned` /
  `invalid`) so operators can see exactly what changed. Invalid
  paths — resource names containing `/`, KV paths that fail
  `canonicalize_kv_path` — are surfaced in the `invalid` array
  instead of silently dropping. `dry_run = true` reports the same
  counts without writing any owner records.
- **Sharing is live.** `scopes = ["shared"]` is wired end-to-end
  against the `ShareStore`; see `src/modules/identity/share_store.rs`
  and the `v2/identity/sharing/*` handlers.
- **Tenants carry an implicit shared-target grant.** A namespace is
  created with default mounts but no policies, and a namespace-bound
  token resolves its named policies from that empty keyspace — so it
  held no rule at all on its own namespace's `secret/`, `resources/`,
  or `resource-group/` mounts. `new_acl_inner` now injects
  `namespace-shared` (alongside the existing `namespace-self`) for any
  non-root binding: the `{{namespace.path}}`-templated mirror of the
  shared-target block in `default`. Templated rather than literal
  because these mounts *are* path-rewritten —
  `rewrite_request_for_namespace` turns `resources/resources/db1` into
  `<ns>/resources/resources/db1` — so the rules resolve to the token's
  own namespace and can never reach a sibling tenant. Same
  `scopes = ["shared"]` discipline as `default`: no share, no access.

### Per-user scoping inside a namespace

Two layers had to change for `owner` / `shared` to work for a tenant.

**Path shape.** `rewrite_request_for_namespace` prepends `<ns>/` to every
non-header-scoped request, so the ACL sees
`dti/esi/resources/resources/db1`. The shape helpers in
`src/modules/policy/policy_store.rs` (`resource_name_from_path`,
`file_id_from_path`, `asset_group_name_from_path`, `looks_like_kv_path`)
matched root-relative paths only, so they extracted no target name and
`resolve_target_shared_caps` / `resolve_asset_owner` /
`resolve_asset_groups` / `filter_list_by_ownership` all returned empty —
fail-closed, but it made sharing unusable for tenants. They now take the
active namespace and strip it via `mount_relative_path` before matching.

**Storage key.** Resource, file, and asset-group owner/share records were
keyed on the bare name (`sys/owner/resource/<name>`, share target
`resource|<name>`) while the objects live in namespace-isolated storage,
so root's `db1` and a tenant's `db1` shared one owner record and one
share set. Stripping the prefix alone would therefore have turned a
fail-closed miss into a cross-namespace grant. Keys are now
`<ns>/<name>` via `OwnerStore::scope_target_name`, the name-keyed
analogue of `canonicalize_kv_path_scoped`. Root keeps the bare form
byte-for-byte; namespaced owner records live in separate
`owner/ns-resource/` and `owner/ns-file/` sub-views under a
base64url'd key, so the two forms share no keyspace and cannot collide.
Share targets need no keyspace split — `target_hash` already base64s
`<kind>|<canonical>`, and `resource|db1` cannot hash to
`resource|dti/esi/db1`.

Scoping is applied at the *boundaries*, not inside the stores: the store
methods still take one key string, and each caller scopes first
(`scope_share_target` for the share endpoints, `scope_target_name` for
owner read/transfer/backfill, resource rename, and file create). This
matches how KV already worked and keeps the diff auditable.

The scoped key is an internal detail and must not escape in responses.
`display_share_target` is the inverse of `scope_share_target` and runs on
every `target_path` leaving the share endpoints, so a caller gets back
the mount-relative name it supplied. This matters because clients treat
`target_path` as the object's name — the GUI passes it to
`readResource(name)` and renders it — so returning `dti/esi/db1` made
shared resources unopenable and printed the key in the UI. Only the
*active* namespace's prefix is stripped, so a record from another
namespace is never rewritten into a local-looking name. The audit /
sharing-history aggregator deliberately keeps the full scoped key, where
being unambiguous matters more than being pretty.

#### Migration

`src/modules/identity/ns_scope_migrate.rs` re-keys pre-existing bare
records once, on the first unseal after upgrade. Nothing in a legacy
record names its namespace — that is the bug — so the owning namespace
is inferred from where the object lives: each namespace's `resource`
mounts are read from its own mount table and their `meta/<name>` keys
listed. Root-held names are left bare (already correct, and root wins
over any tenant of the same name); a name held by exactly one namespace
is re-keyed; orphans and names held by two or more namespaces are left
bare and logged, since guessing could transfer access between tenants.
A version marker under the namespace registry makes it idempotent, and
each record is written-new-then-deleted-old so an interrupted run leaves
a resolvable duplicate rather than an orphan.

#### Still open: the asset-group store

`ResourceGroupStore` (group records, member index, secret index, file
index) remains a single root-global keyspace keyed on the bare name, so
asset groups are not yet per-namespace. Asset-group *share targets* are
scoped by this release, which means a tenant's group-mediated access now
fails closed instead of resolving against a root group of the same name.
`PolicyStore::can_operate` is likewise namespace-blind — it is a
cross-target preview that does not carry the triggering request's
namespace, and a miss only narrows the preview.

### Integration tests

Three tests in `src/modules/identity/mod.rs`:

1. `test_per_user_scoping_owner_denies_non_owner` — alice writes a
   KV-v2 secret; bob (also `secret-author`) is denied on read.
2. `test_secret_author_full_crud_on_owned_secret` — carol writes,
   reads, updates, and deletes her own secret end-to-end.
3. `test_list_filter_by_ownership` — bob listing
   `secret/metadata/` sees only his own keys; alice's secrets are
   filtered out of the response.
