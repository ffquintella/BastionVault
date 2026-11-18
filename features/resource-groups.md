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
    secrets:      Vec<String>,           // KV secrets by own name (format 1); deduped, sorted
    secrets_format: u32,                 // 0 = pre-T507 keys, 1 = own names (T507)
    legacy_secrets: Vec<String>,         // the format 0 list a migrated record replaced (rollback only)
    created_at:   RFC3339 String,
    updated_at:   RFC3339 String,
}
```

**Resource members** are canonicalized on write: trimmed, lowercased,
deduped, sorted lexicographically. Entries that are empty or contain
`/` or `..` are silently dropped.

**KV-secret members** are each secret's own `<mount>/<name>`,
namespace-relative, stored as given (T507, record format 1): whitespace and
surrounding slashes trimmed, a `..` segment dropped, nothing stripped,
case preserved. On a KV v2 mount `secret/data/x` is the secret named
`data/x` and `secret/x` the secret `x` through every route; on a kv
(version 1) mount `kv/data/x` is the secret `data/x`. A request looks up
the key `policy::kv_target` derives through the mount table, the same one
owner and share records use (T499): a `destroy/` or `undelete/` request its
secret's, a path no KV mount serves itself, a KV path that names no secret
(T506) nothing.

Before T507 (format 0) a member and a request path lost a `data` or
`metadata` second segment whatever the mount, so on a kv mount `kv/x`,
`kv/data/x` and `kv/metadata/x` were one member, a multi-segment KV v2
mount's member named one route (`team/kv/data/z` matched only `data/`
requests), and any edit of a group re-keyed a KV v2 member such as
`secret/data/x` (the secret `data/x`) to `secret/x`. The T507 migration
(`resource_group/secret_name_migrate.rs`) runs at unseal, after the T499
datafix, and converts each format 0 member to every own name a pre-T507
lookup reached it by, through its namespace's stored mount table: exactly
the access it gave. A member that reached several secrets (every kv v1
member: `kv/x` reached `x`, `data/x` and `metadata/x`) keeps all of them and
is logged on the `migration` target, key names only, and counted, so
operators can prune; a member no mount serves is kept as written. Each
converted record keeps its old list in `legacy_secrets` for rollback;
downgrading after the migration is unsupported. The conversion is per
record and atomic (one write), skips converted records, and is retried by
the T511 background retry and at every unseal. Until its marker
(`resource-group/meta/secret-names`) is set, lookups use the pre-T507 keys
and the legacy index, and any change to which secrets a group lists, a
delete of a group listing secrets, and a delete of a listed secret answer
503 (`docs/api.md`, "Asset-group key switch pending"); once set, no store
method writes a format 0 record with members again. A format 0 record a
`.bvx` import writes raw later is converted by `reindex` or the group's
next write.

### Storage

All data is encrypted behind the vault barrier via the system view.
Primary record plus two parallel reverse indexes plus change history:

```
sys/resource-group/group/<name>                    -> ResourceGroupEntry (JSON)
sys/resource-group/member-index/<resource>         -> Vec<String>  (group names)
sys/resource-group/secret-index/<b64url(path)>     -> Vec<String>  (group names; pre-T507 keys)
sys/resource-group/secret-name-index/<b64url(name)> -> Vec<String>  (group names; own names, T507)
sys/resource-group/file-index/<file-id>            -> Vec<String>  (group names)
sys/resource-group/history/<name>/<20-nanos>       -> ResourceGroupHistoryEntry
```

That is the **root** scope (its `meta/` keyspace also holds the T507
marker). Every other namespace has its own scope with the same keyspaces under
`sys/resource-group/ns/<b64url(namespace path)>/` — see
[Namespace scoping](#namespace-scoping).

The **member-index** handles resource membership keyed by the bare
resource name. The **secret-name-index** handles KV-secret membership
keyed by `base64url(no-pad)` of the secret's own name — base64url avoids
`/` characters that would otherwise interact with the BarrierView key
scheme. The **secret-index** holds the pre-T507 keys; it decides only
while the T507 switch is pending, and is kept, not read, afterwards.

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
- A gated rule's path matches exactly what the same rule matches
  ungated, including a `+` rule ending in `*` (`kv/+/*`, a prefix rule on
  its last segment). Until T121 such a gated rule matched nothing.

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
  `cubbyhole/`, `resources/`, `files/`) is a candidate. Its key is the
  secret's own name through the mount table (`secret_names::request_key`,
  T507): KV-v2 `secret/data/foo/bar`, `secret/metadata/foo/bar` and the
  short form `secret/foo/bar` are the secret `secret/foo/bar`; KV-v1
  `kv/data/foo` is the secret `kv/data/foo`, not `kv/foo`.
- Both lookups run independently and their results are unioned —
  `Request::asset_groups` may contain group names from either source.
  A single policy rule's `groups = [...]` filter passes as long as the
  target matches through either path.

### Namespace scoping

Asset groups belong to the namespace they were created in. Before this,
the store was one root-global keyspace keyed on the bare name, so every
namespace listed every group (a group created in `dti/importacao/test02`
showed everywhere) and a tenant's `db1` and root's `db1` shared one
`member-index/db1` row, feeding each other's `groups = [...]` qualifier.

**Storage.** Each namespace is a *scope* with its own group records,
member / secret / file indexes and history. Root keeps the original keys,
so every record written before scopes existed reads as a root group with
no migration. A namespace scope lives under
`sys/resource-group/ns/<b64url(path)>/{group,member-index,secret-index,file-index,history}/`
(the identity store's `identity-ns/` convention). The two cannot collide:
group names may not contain `/`, and the namespace is one base64url key
segment.

**Visibility.** A group created in namespace `a` is visible in `a` and in
every descendant (`a/b`, `a/b/c`), never in a sibling or a parent. Root's
groups are therefore visible everywhere.

| Operation | Scope it acts on |
|-----------|------------------|
| `LIST groups` | own scope plus every ancestor; a nearer scope shadows a farther one of the same name |
| `GET groups/<name>`, `…/history` | own scope, then ancestors nearest first; the response carries `namespace` (the home scope, `""` = root) and `inherited` |
| `PUT groups/<name>` | own scope only. A name only an ancestor holds creates a new group here that shadows it; the response carries a warning and the inherited group is untouched |
| `DELETE groups/<name>` | own scope only; deleting a group that exists only in an ancestor is refused with 403 |
| `by-resource`, `by-secret`, `reindex` | own scope only |
| `groups = [...]` ACL qualifier, list filter, KV/file/resource prune, rename | own scope only, keyed by the target's mount-relative name |
| `sys/asset-group-owner/transfer` | own scope only (a header naming an unknown namespace is refused, not read as root) |

The reverse indexes are never inherited: an inherited group's members are
the ancestor's objects, not the child's objects of the same name. For the
same reason, member redaction and the list's member pass probe an inherited
group's members in its **home** namespace, so a tenant user who can read
the tenant's `web1` does not see root's `web1` through root's group.

**Owner and shares.** The owner lives on the record, so it is the home
scope's. Asset-group share targets are keyed `<home ns>/<name>` (bare at
root) as before; a read of an inherited group consults the shares of its
home namespace, a write consults the requesting namespace's. A share key
that resolves to no namespace is skipped, never read from another scope.

**Addressing.** Handlers check that the request was routed to its own
namespace's `resource-group/` mount. The path-prefix form
(`/v1/<ns>/resource-group/…` without the namespace header) reaches a tenant
mount with no namespace on the request and is refused with 400 rather than
acting on root's groups. Only the default `resource-group/` mount path is
served.

**Exchange (`.bvx`).** A namespace bundle exports and imports exactly its
own scope's group records (`MountIndex::resource_group_prefix`); inherited
groups belong to the ancestor's export. Group ids are refused unless they
are a single key segment. Imports write the primary records only, so run
`resource-group/reindex` in that namespace afterwards (unchanged).

### Batch read, change version and caches

The GUI's Resources and Secrets pages used to LIST the groups and then GET
each one (~150 requests per page view, each probing every member for
redaction and writing its own audit entry). Phase 15 replaces that with one
request and a cheap revalidation.

**Batch read** — `GET resource-group/v2/groups/batch[?shape=full|slim][&since=]`
(v2 only; v1 is frozen). It returns every group the caller may both list and
read on its own, so it is exactly "LIST, then GET each, keep the successes":

1. The `LIST groups` visibility rule (admin, owner, share, member pass), via
   one helper shared with `handle_list` so the two cannot drift.
2. Per group, the ACL decision `GET groups/<name>` gets in the request's
   namespace (owner and share scopes resolve against the group's home). A
   group the caller may list but not read is withheld, so the batch is not a
   way around `groups/+`.
3. Member redaction identical to `handle_read`: root/admin callers and a
   group's owner see it whole; every other member is probed in the group's
   home namespace. `PolicyStore::can_operate_many` gives the same verdict as
   `can_operate` (which now delegates to it) from one ACL build per namespace,
   and each distinct member is probed once per call.

`shape=full` returns each group as `GET groups/<name>` does. `shape=slim`
returns names plus `by_resource` / `by_secret` / `by_file` maps over the
namespace's **own** groups only (an inherited group's members are its
ancestor's objects; keying them would pin the group on this namespace's
same-name objects, the reason the reverse index never inherits), with hidden
members left out. Slim still redacts: skipping the probes would put the names
of members the caller cannot read into the map keys. One request is one audit
entry; the per-group work happens inside the handler. The `shape` and `since`
query keys are on `bv_logical`'s query allowlist, since the endpoint is a read.

**Change version** — each scope stores `resource-group/meta/version` (root) or
`resource-group/ns/<b64url(ns)>/meta/version`: `{format: 1, counter, stamp}`,
in vault storage so HA nodes agree. Every mutation bumps it after its data
writes — `set_group`, `delete_group` (of a group that existed), `set_owner`,
`rename_resource`, the three prunes (when they removed something) and
`reindex` — and the `.bvx` importer bumps it after writing group records. A
read never does. A scope with no record (every scope before phase 15) reads as
counter 0; the first mutation writes format 1. `counter` rises by one per bump
for writers that do not race; racing bumps (two nodes) can write the same
counter, so change detection compares the whole record, and `stamp` is unique
per bump. The batch's `version` is a BLAKE3 digest over the records of the
request's scope and every ancestor, so a child sees a change in any ancestor
and never a sibling's. The handler reads the version before any group: a
write in between pairs the old version with newer data (one extra refetch),
never a new version with old data. An unreadable record makes `version` `null`
(fail closed: never "unchanged"); the next mutation replaces it with a warning.

**Client cache** — `gui/src/lib/assetGroupCache.ts` holds one batch answer per
shape, keyed by namespace and a token fingerprint, served for 45 s and then
revalidated with `since` (also on window focus, on mount when stale and on a
45 s tick while a page is open), stale-while-revalidate. A full read happens at
least every 5 minutes, because `version` covers group data, not the caller's
grants (a new share or policy does not move it). This client's own group
writes, deletes and owner transfers (the `lib/api` wrappers, so the asset-group
page and the PMP import are covered), logout, session expiry and a namespace
switch drop it and notify open pages at once. Against a server without the
route it falls back to LIST + GET each.

**No server-side reverse-index cache.** The `groups = [...]` qualifier reads the
reverse index per request, and caching it was considered and rejected: a cache
that is never stale must re-read the version record per lookup, which is the
same single storage read the uncached lookup costs, so it saves nothing; a
TTL-bounded one would let another HA node keep granting access through a
membership that was removed, and raw writers (`.bvx` import, backup restore)
bypass in-process invalidation. The batch read already reads each group record
once per call.

### Implementation notes

- Group names are case-insensitive (lowercased on write); member names
  are likewise normalized to lowercase.
- A write that fails to update the reverse index surfaces as a
  top-level error and the caller must retry. The reindex endpoint is
  the recovery path for any divergence.
- The store is persisted and uncached; see "No server-side reverse-index
  cache" above for why the per-request qualifier lookup stays that way.

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
| 13 | Ownership, admin transfer, sharing (depends on per-user-scoping) | Done (`OwnerStore` integration; `POST /v2/sys/asset-group-owner/transfer`; `ShareTargetKind::AssetGroup` with indirect member-expansion at authorize time; member redaction for non-owner / non-admin readers) |
| 14 | Namespace scoping: per-namespace store, ancestor inheritance (read-only), per-namespace reverse indexes and `groups` qualifier, `.bvx` per-namespace groups | Done |
| 15 | v2 batch read (`full` / `slim`), persisted per-scope change version with `since` revalidation, shared GUI cache; server-side reverse-index cache rejected | Done |
| 16 | KV-secret members keyed on the secret's own name (record format 1), migration of stored members keeping their access exactly, pending-switch refusals, GUI chips by own name (T507) | Done |

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
6. `test_resource_group_secret_membership_by_own_name` — secrets are
   stored as given (trimmed, deduped, nothing stripped); `by-secret`
   finds each by its own name and not another secret's; removing a
   secret clears the reverse index. The T507 behaviour and migration are
   in `src/engine_tests/asset_group_secret_names.rs`.
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

Phases 13 (ownership / admin transfer / sharing) and 14 (namespace
scoping, see [Namespace scoping](#namespace-scoping)) are done. Tests for
14 live in `src/engine_tests/kernel_resource_group.rs`
(`test_asset_group_visible_in_own_namespace_and_descendants_only`,
`test_asset_group_member_index_is_per_namespace`,
`test_legacy_bare_key_asset_group_reads_as_root`,
`test_child_cannot_modify_or_delete_inherited_asset_group`,
`test_inherited_asset_group_members_are_probed_in_their_home_namespace`)
and in `group_store.rs`'s unit tests.

Phase 15 (see [Batch read, change version and caches](#batch-read-change-version-and-caches))
is done. Tests: `group_store.rs` unit tests (every mutation kind bumps, no read
does, scopes are independent, a child's token follows its ancestors, an
unreadable record fails closed), `src/engine_tests/kernel_resource_group.rs`
(`test_asset_group_batch_*`: batch = LIST + GET each for admin and non-admin
callers, redaction, a listable-but-unreadable group withheld, `since`,
namespaces and inheritance, one audit entry), the `.bvx` import bump in
`src/exchange/scope.rs`, and `gui/src/test/assetGroupCache.test.ts`.

Still open after phase 14:

- Groups created inside a namespace *before* phase 14 sit in the root
  keyspace and therefore read as root groups, visible everywhere. Nothing
  in a legacy record names its namespace, so they are not moved
  automatically; a root operator re-creates them in the right namespace and
  deletes the root copy.
- The audit page's asset-group source reads the root scope only, like the
  policy and identity-group sources beside it.
- Rustion and ssh-broker policy tiers are keyed on bare asset-group names
  (`rustion/policy/asset-group/<id>`), so a tenant group with the same
  name as a root group matches the same tier record.
- Deleting a namespace does not purge its `resource-group/ns/<b64>/`
  sub-tree (the same as `identity-ns/` and `policy-ns/`).

Resource groups compose cleanly with identity groups: an identity
group can attach a policy with `groups = [...]`, giving "this team
gets this bundle" in one group edit without a policy rewrite.
