# Resource Groups

Status: Backend + HTTP API **Done**. Resource-delete lifecycle hook
**Done**. ACL `groups = [...]` qualifier **Done** (both resource and
KV-secret halves). KV-secret membership **Done**. KV-delete lifecycle
hook **Done**. List-filter on group-gated LIST operations **Done**.
Policy-compile warning for unknown groups **Done**. GUI integration
**Done** (Asset Groups page, chips, Termius-style section, filter).
Ownership, admin transfer, and sharing still pending on
per-user-scoping.

> The internal module name (`resource_group`, mount `resource-group/`)
> and the feature name now diverge: the backend actually stores both
> resources and KV secrets, matching the operator-facing "asset group"
> name from `features/asset-groups.md`. We kept the internal name to
> avoid a breaking migration of storage keys and mount paths; the
> operator-facing label in docs and (eventually) the GUI is still
> "Group".

## Goal

Provide a way for operators and end users to organize resources into
named collections — "project-phoenix", "office-routers", "customer
ACME" — and look up "which groups is this resource in?" cheaply.

This is the resource-scoped subset of the broader design captured in
[asset-groups](asset-groups.md). Resources are the natural starting
point: they are a small, well-bounded namespace (unlike KV paths, which
need canonicalization across v1/v2 and mount aliases), and the GUI
already treats resources as first-class objects with a structured
metadata schema.

## Relationship to other features

- **Identity groups** (`features/identity-groups.md`) bundle *principals*
  and attach *policies* to them.
- **Resource groups** (this feature) bundle *objects* (resources). In
  this phase the store only maintains the data and the reverse index.
  The ACL integration that lets a policy reference a resource group via
  a `groups = [...]` qualifier is tracked in [asset-groups](asset-groups.md)
  and will be added in a later phase; until then resource groups act as
  an organization layer without changing authorization.
- **Asset groups** (`features/asset-groups.md`) is the full story that
  also covers KV secrets, ownership, sharing, and the ACL extension.
  Resource groups ship the resource-only half first; KV-secret
  membership will be layered on later.

## Design

### Data model

```
ResourceGroupEntry {
    name:         String,                // lowercased, no "/" or "..", unique
    description:  String,
    members:      Vec<String>,           // resource names; lowercased, trimmed, deduped, sorted
    secrets:      Vec<String>,           // KV paths (canonical form); deduped, sorted
    created_at:   RFC3339 String,
    updated_at:   RFC3339 String,
}
```

**Resource members** are canonicalized on write: trimmed, lowercased,
deduped, sorted lexicographically. Entries that are empty or contain
`/` or `..` are silently dropped.

**KV-secret members** are canonicalized on write by:

- Trimming whitespace and surrounding slashes.
- **Stripping the `data/` or `metadata/` segment** that KV-v2 inserts
  between the mount and the logical key. So `secret/foo/bar`,
  `secret/data/foo/bar`, and `secret/metadata/foo/bar` all map to the
  single canonical form `secret/foo/bar`.
- Case-preserving (KV keys are case-sensitive on the storage backend).
- Rejecting `..` segments to avoid path-traversal collisions in the
  reverse-index key space.

The canonicalization is heuristic: a mount literally named `data` or
`metadata` would be misclassified. This is documented and accepted for
v1 given how unusual such mount names are.

### Storage

All data is encrypted behind the vault barrier via the system view.
Primary record plus two parallel reverse indexes plus change history:

```
sys/resource-group/group/<name>                    -> ResourceGroupEntry (JSON)
sys/resource-group/member-index/<resource>         -> Vec<String>  (group names)
sys/resource-group/secret-index/<b64url(path)>     -> Vec<String>  (group names)
sys/resource-group/history/<name>/<20-nanos>       -> ResourceGroupHistoryEntry
```

The **member-index** handles resource membership keyed by the bare
resource name. The **secret-index** handles KV-secret membership keyed
by `base64url(no-pad)` of the canonical path — base64url avoids `/`
characters that would otherwise interact with the BarrierView key
scheme.

Both indexes are maintained by `set_group` / `delete_group`: each
write diffs old vs new `members` and old vs new `secrets`, and
updates only the index entries that actually changed. Either index
can be rebuilt from the primary records via the `reindex` endpoint
in case a write is interrupted mid-way and the primary and index
records drift apart.

### Module wiring

- `src/modules/resource_group/group_store.rs` — `ResourceGroupStore`
  owns three `BarrierView` sub-views (group, member-index, history) and
  exposes CRUD, `groups_for_resource`, `prune_resource`, `reindex`, and
  history helpers.
- `src/modules/resource_group/mod.rs` — `ResourceGroupModule` registers
  a logical backend factory at `setup()` time so the `resource-group/`
  mount binds on first unseal. The store is created in `init()` (which
  runs after unseal) and exposed via an
  `ArcSwap<Option<Arc<ResourceGroupStore>>>`. Handlers resolve the
  store lazily via the module manager.
- `src/module_manager.rs` — `ResourceGroupModule` is added to the
  default module list so it loads alongside the other core modules.
- `src/mount.rs` — `resource-group/` is added to `DEFAULT_CORE_MOUNTS`
  for new deployments. The existing `mount_update` migration injects
  any missing default core mounts without overwriting existing
  entries, so upgrading deployments pick up the mount on next unseal.

### HTTP API

Mounted at `resource-group/`. Routes:

| Method | Path                                                      | Purpose |
|--------|-----------------------------------------------------------|---------|
| LIST   | `/v1/resource-group/groups`                               | List group names |
| GET    | `/v1/resource-group/groups/{name}`                        | Read a group |
| PUT    | `/v1/resource-group/groups/{name}`                        | Create or update (partial updates preserve unspecified fields) |
| DELETE | `/v1/resource-group/groups/{name}`                        | Delete a group |
| GET    | `/v1/resource-group/groups/{name}/history`                | Change history, newest first |
| GET    | `/v1/resource-group/by-resource/{resource}`               | List groups a resource belongs to |
| GET    | `/v1/resource-group/by-secret/{b64url_path}`              | List groups a KV path belongs to; the `b64url_path` segment is `base64url(no-pad)` of the KV path. Canonicalizes v1 / v2 variants server-side, so either form decodes to the same result. |
| PUT    | `/v1/resource-group/reindex`                              | Rebuild both reverse indexes from primary records (admin-only) |

Write-payload fields:

- `description` (string).
- `members` (comma-separated string or array of strings) — resource names.
- `secrets` (comma-separated string or array of strings) — KV-secret
  paths. Accepts either the canonical form (`secret/foo/bar`) or the
  KV-v2 API form (`secret/data/foo/bar`, `secret/metadata/foo/bar`);
  stored canonicalized.

Partial updates: supplying only `description` and `members` on a PUT
leaves the existing `secrets` list untouched, and vice versa. Supply
an empty array (`[]`) to explicitly clear a list.

### Change history

Every create/update/delete is appended as a
`ResourceGroupHistoryEntry { ts, user, op, changed_fields, before,
after }`. Values follow the same shape as identity-group history:
`description` is a JSON string, `members` is a JSON array. `members`
is compared as a set, so reordering alone does not record a new
entry. A write that does not change anything is suppressed. Create
entries always record; delete entries retain the full final state in
`before` so the audit trail survives removal.

### Lifecycle hook

`ResourceGroupStore::prune_resource(name)` removes a resource from
every group it is a member of and drops its reverse-index entry. The
resource module's delete handler calls it after the metadata write has
been removed, so deleting a resource automatically tidies every group
it belonged to. Prune failures are logged but do not block the delete;
stale entries can always be repaired with the `resource-group/reindex`
endpoint.

### ACL `groups = [...]` qualifier

Policy HCL grew a new optional attribute on `path` blocks:

```hcl
path "resources/resources/*" {
    capabilities = ["read", "list"]
    groups       = ["project-phoenix"]
}
```

Semantics:

- A capability in a rule with a non-empty `groups` attribute applies
  only when the request target is a member of *any* listed asset
  group. Targets outside every listed group see this rule contribute
  nothing.
- Group names are normalized (trimmed, lowercased, deduped) at
  policy-init time to match the storage form the resource-group
  backend writes.
- Empty `groups` (or omitting the attribute) is the legacy
  literal-path behavior.
- Gated rules are **not merged** with ungated rules on the same path.
  They are stored in a dedicated `ACL::grouped_rules` list and
  evaluated per-rule at authorize time, OR'd into the result. This
  preserves per-rule gate semantics: an ungated `capabilities = ["read"]`
  grant on `resources/resources/*` combined with a gated
  `capabilities = ["update"] groups = ["g"]` on the same prefix yields
  read-always + update-only-in-g, which merging could not represent.
- An explicit `capabilities = ["deny"]` inside a gated rule still
  wipes the grant for matching targets, mirroring ungated deny.

Authorize flow:

1. `post_auth` resolves the request target's resource-group membership
   via `ResourceGroupStore::groups_for_resource` and writes the result
   to `Request::asset_groups`. This is an O(1) reverse-index lookup.
2. The ACL evaluator first runs the existing ungated matchers
   (exact / prefix / segment-wildcard) unchanged.
3. It then iterates `grouped_rules`: each rule whose path matches the
   request and whose `groups` intersect `asset_groups` contributes
   its capabilities. The final caps are the union.

The async group lookup is isolated to `post_auth`, so the sync
evaluator stays sync. If the resource-group subsystem is absent, the
store is not initialized, or the target is not a resource path,
`asset_groups` stays empty and every gated rule is skipped — a safe
default that can only narrow access relative to ungated rules.

Path-shape extraction in `resolve_asset_groups` (policy_store.rs):

- **Resource paths** of the form `resources/resources/<name>` (metadata)
  and `resources/secrets/<name>/...` (per-resource secrets) extract
  `<name>` and consult the member-index via `groups_for_resource`.
- **KV paths**: anything that is *not* one of the fixed non-KV
  prefixes (`sys/`, `auth/`, `identity/`, `resource-group/`,
  `cubbyhole/`, `resources/`) is treated as a candidate KV path and
  passed verbatim to `groups_for_secret`, which canonicalizes
  (stripping `data/` / `metadata/`) before consulting the
  secret-index. KV-v1 `kv/foo`, KV-v2 `secret/data/foo/bar`, and KV-v2
  `secret/metadata/foo/bar` all resolve to the same membership entry.
- Both lookups run independently and their results are unioned —
  `Request::asset_groups` may contain group names from either source.
  A single policy rule's `groups = [...]` filter passes as long as the
  target matches through either path.

### Implementation notes

- Group names are case-insensitive (lowercased on write); member names
  are likewise normalized to lowercase.
- A write that fails to update the reverse index surfaces as a
  top-level error and the caller must retry. The reindex endpoint is
  the recovery path for any divergence.
- The store is persisted — no cache layer in v1. Authorization checks
  will read the reverse index per request once the ACL grammar
  extension lands; a bounded LRU keyed by `resource_name -> groups` can
  be added then if needed.

## Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | `ResourceGroupStore` + CRUD + reverse index + history under system barrier | Done |
| 2 | HTTP API: list/read/write/delete + `by-resource` + `reindex` + history | Done |
| 3 | Integration tests (CRUD, reverse-index maintenance, history) | Done |
| 4 | Default mount + migration in `mount_update` | Done |
| 5 | Lifecycle hook: call `prune_resource` on resource-delete | Done |
| 6 | ACL `groups = [...]` qualifier + evaluator integration (resource half) | Done |
| 7 | KV-secret membership: `secrets` field, secret-index, canonicalization, `by-secret` route | Done |
| 8 | ACL `groups = [...]` qualifier extended to KV paths via secret-index | Done |
| 9 | KV-delete lifecycle hook: call `prune_secret` when a KV entry is destroyed | Done (PolicyStore::post_route) |
| 10 | List-filter: narrow LIST response keys to asset-group members when granted via `groups = [...]` | Done |
| 11 | Policy-compile warning when `groups = [...]` references a non-existent asset group | Done |
| 12 | GUI: Asset Groups page, group chips on objects, sidebar filter | Done |
| 13 | Ownership, admin transfer, sharing (depends on per-user-scoping) | Pending |

## Testing

Ten integration tests in `src/modules/resource_group/mod.rs`:

1. `test_resource_group_crud` — create/read/list/update/delete with
   partial-update preservation and member canonicalization; verifies
   the `secrets` field is present and empty when not supplied.
2. `test_resource_group_reverse_index` — a resource in two groups is
   visible in both via `by-resource`; removing the resource from one
   group narrows the lookup; deleting a group drops the lookup to
   empty.
3. `test_resource_group_history` — create + update produce history
   entries with correct `op`, `changed_fields`, and before/after
   values. Entries are returned newest-first.
4. `test_resource_delete_prunes_from_groups` — deleting a resource
   removes it from every group it was a member of and clears its
   reverse-index entry.
5. `test_resource_group_acl_groups_qualifier` — a user whose policy
   grants read on `resources/resources/*` only via `groups = ["club"]`
   can read a resource in "club" but is denied on a resource outside
   it. Moving the resource in/out of the group takes effect on the
   next request without re-login.
6. `test_resource_group_secret_membership_and_canonicalization` —
   secrets supplied in canonical, `data/`, and `metadata/` forms all
   collapse to the same two entries; `by-secret` accepts
   base64url-encoded queries and returns the matching groups for any
   of the three forms; removing a secret clears the reverse index.
7. `test_resource_group_acl_groups_qualifier_kv` — the same ACL gate
   enforces access against a KV-v1 mount: a user with a
   `groups = ["kv-club"]` policy reads `kv/alpha` (in the group), is
   denied on `kv/beta` (outside it), and swaps correctly when
   membership changes.
8. `test_list_filter_on_groups_gated_list_kv` — a user whose only
   list grant on `kv/*` is gated by `groups = ["crew"]` sees only
   the crew's members in the list response; non-members are filtered
   out of `keys`.
9. `test_kv_delete_prunes_from_groups` — deleting a KV secret
   removes it from every asset group it belonged to via
   `PolicyStore::post_route`.
10. `test_policy_write_warns_on_unknown_groups` — writing a policy
    whose `groups = [...]` clause names a nonexistent group
    succeeds but returns a response warning listing the unknown
    names; existing groups are not flagged.

## Current State

Phases 1–12 are shipped. The feature is feature-complete for the
single-tenant, non-ownership model:

- Object storage for resources and KV secrets, with two parallel
  reverse indexes and canonicalization that collapses KV-v1/v2 forms.
- HTTP CRUD API, `by-resource` / `by-secret` reverse lookups,
  `reindex` admin recovery endpoint, change-history with before/after
  values.
- Default mount + `mount_update` migration on unseal for upgrading
  deployments.
- Lifecycle hooks on both sides: resource-delete prunes in the
  resource module, KV-delete prunes via `PolicyStore::post_route`
  (registered as both `AuthHandler` and `Handler` in the core
  pipeline).
- ACL `groups = [...]` qualifier parsed into `PolicyPathRules.groups`,
  stored unmerged in `ACL::grouped_rules`, evaluated per-rule.
  `PolicyStore::post_auth` populates `Request::asset_groups` via a
  single reverse-index lookup.
- **List-filter** when a LIST op is authorized only via a gated rule:
  the evaluator records the rule's `groups` on
  `ACLResults::list_filter_groups`, `post_auth` propagates them to
  `Request::list_filter_groups`, and `PolicyStore::post_route`
  narrows the response `keys` to entries whose full logical path is a
  member of any listed group. Ungated LIST grants defeat the filter
  so broader access is never accidentally narrowed.
- **Policy-compile warning** when a policy's `groups = [...]` clause
  references a group name that does not currently exist. The write
  still succeeds (a later group create retroactively activates the
  clause), but the response carries a warning listing the unknown
  names so operators can spot typos.
- GUI: Asset Groups page (`/asset-groups`), Termius-style groups
  section on the Resources and Secrets pages with click-to-filter and
  a breadcrumb-style path indicator, chips on individual resources
  and secrets, collapsible Admin section with persisted state.

Remaining: phase 13 (ownership / admin transfer / sharing), blocked
on [per-user-scoping](per-user-scoping.md) landing the entity-ID
plumbing and the `SecretShare` type the sharing layer will hang off.

Resource groups compose cleanly with identity groups: an identity
group can attach a policy with `groups = [...]`, giving "this team
gets this bundle" in one group edit without a policy rewrite.
