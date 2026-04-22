# Asset Groups (Secrets & Resources Groups)

Status: **Feature-complete.** Every item from the original design
is shipped: both halves of the object model, reverse indexes, HTTP
API, history, lifecycle prunes, list-filter on group-gated LIST ops,
policy-compile warnings for unknown groups, end-to-end ACL `groups`
qualifier, ownership with first-write capture + admin transfer, the
`ShareTargetKind::AssetGroup` sharing integration with indirect
resolution at authorize time, and the GUI. **Member redaction** is
now live too: non-owner / non-admin callers who can read the group
but not a specific member see `<hidden>` in the member list, with a
summary row in the GUI describing how many entries are hidden.
Group cardinality stays truthful without leaking paths.

See `features/resource-groups.md` for the concrete implementation. The
internal module name is still `resource_group` (mount
`resource-group/`, storage under `sys/resource-group/…`) for
backward-compatibility with the resource-only ship; the operator-facing
label remains "Group".

All work items from the design are **done**, including member
redaction on read.

> *Terminology:* internally the feature is called an **asset group** to
> disambiguate from **identity groups** (which group *principals* —
> users and AppRoles — rather than *objects*). The operator-facing name
> in the GUI is "Group", with UI context making the kind unambiguous.

## Goal

Provide a way for operators and end users to:

1. **Organize** secrets and resources into named collections that reflect
   how people actually think about them — "project Phoenix", "office
   network gear", "customer ACME", "shared platform credentials" —
   without forcing a specific path hierarchy on KV mounts or naming
   convention on resources.
2. **Grant access by collection.** A policy can reference an asset
   group by name and have its capabilities apply to every current and
   future member of that group, so membership edits do not require
   policy edits.

A single asset group can mix KV secrets and resources; a typical real
group is "everything about project X", which spans both kinds.

## Relationship to existing features

- **Identity groups** (`features/identity-groups.md`) bundle *principals*
  and attach *policies* to them. Membership is UserPass usernames or
  AppRole role names.
- **Asset groups** (this feature) bundle *objects* and are *referenced
  from* policies. Membership is KV secret paths and resource names.
- **Per-user scoping** (`features/per-user-scoping.md`) adds
  ownership-based scopes (`owner`, `shared`) to policy paths. Asset
  groups add a third orthogonal scope: `groups`.

The three features compose: a policy can grant `read` on `resources/*`
with `scopes = ["owner"]` *and* `groups = ["project-phoenix"]`, meaning
"the caller can read every resource they own **or** every resource in
the `project-phoenix` asset group". Groups attached to identity groups
can reference asset groups, giving a clean two-level indirection —
*"platform engineers" get the `project-phoenix` bundle*.

## Design

### 1. Data model

```
AssetGroupKind (implicit per-member):
    "kv-secret"   — a KV-v1 or KV-v2 path like "secret/data/foo/bar"
    "resource"    — a resource name like "server-01"

AssetGroupMember {
    kind: AssetGroupKind,
    path: String,        // full addressable path; canonicalized on write
}

AssetGroup {
    name:             String,                     // lowercased, no "/" or "..", unique
    description:      String,
    members:          Vec<AssetGroupMember>,      // deduped, sorted
    owner_entity_id:  String,                     // entity that created it; editable by admins only
    created_at:       RFC3339,
    updated_at:       RFC3339,
}
```

Group names are case-insensitive (lowercased on write) and must not
contain `/` or `..`.

Members are canonicalized on write:

- KV paths are stored as the logical read path (e.g., `secret/data/foo`
  for KV-v2), not the metadata path. The evaluator handles both forms
  when it consults the reverse index.
- Resource names are stored as-is, lowercased.
- Duplicates are collapsed. Order is lost (the store returns a
  lexicographically sorted members list).

### 2. Storage

Primary record plus two reverse indexes, all encrypted behind the
system barrier view:

```
sys/asset-group/<name>                         -> AssetGroup (JSON)
sys/asset-group-by-secret/<base64url(path)>    -> Vec<String>   (group names)
sys/asset-group-by-resource/<resource_name>    -> Vec<String>
```

Reverse indexes are maintained by the write handler. Key design points:

- Base64url of the secret path in the reverse-index key avoids nested
  storage paths while keeping the key deterministic. A short
  non-cryptographic hash suffix could replace it once cardinality is
  understood; the design keeps the reversible form so audit tooling
  can decode it.
- Membership writes are not atomic across records and indexes. The
  write handler retries the index update once; if the retry also
  fails, the index is flagged stale and a background `reindex` job
  rebuilds it from the primary records on next unseal. A
  `sys/asset-group-reindex` maintenance endpoint triggers it manually.
- The store is persisted — no cache layer in v1. Authorization checks
  read the reverse index per request; if this becomes a hotspot a
  small bounded LRU keyed by `(kind, path) -> [group names]` can be
  added later.

### 3. Authorization integration: the `groups` qualifier

Extend the ACL grammar (together with the `scopes` qualifier from
per-user-scoping) with a `groups` list on a policy path:

```hcl
path "secret/data/*" {
    capabilities = ["read", "list"]
    groups       = ["project-phoenix", "shared-platform"]
}

path "resources/*" {
    capabilities = ["create", "read", "update", "list"]
    groups       = ["project-phoenix"]
    scopes       = ["owner", "shared"]
}
```

Semantics:

- `groups = [...]` attached to a path rule is a **membership filter**.
  A capability in that rule applies only when the request target is a
  member of *any* listed asset group.
- `groups` is **additive with `scopes`**: if both qualifiers are
  present, the rule applies when the target matches `scopes` *or* is in
  any listed group. This matches the intuitive "give me read on my own
  stuff plus anything in the project group" use case.
- On `list` operations, the backend filters returned keys to the
  allowed set before serializing, mirroring the `owner`/`shared` list
  behavior.
- Omitting `groups` (or passing `groups = []`) keeps the rule's current
  literal-path semantics.

Authorization check flow per request (extending the per-user-scoping
flow):

1. Resolve the caller's ACL (with templating, if any).
2. Match request path against each rule, gathering capability sets as
   today.
3. For each matching rule with a non-empty `groups` list, look up the
   target's groups via the reverse index and keep the rule's caps
   only if the intersection with the rule's `groups` is non-empty.
4. For matching rules with a non-empty `scopes` list, apply the
   per-user-scoping check as usual.
5. A rule contributes its capabilities if *either* the group filter or
   the scope filter (whichever is present) passes. If both are present,
   they OR together.
6. Union capabilities across all matching rules.

### 4. Membership semantics on target lifecycle

- **Rename of a resource** — resources support a delete+create pattern
  today; no in-place rename. If one is added later, the handler must
  walk `sys/asset-group-by-resource/<old>` and rewrite the affected
  group records. Until then, renames manifest as delete+create from the
  group's perspective.
- **Move of a KV secret** — same story: delete + create. The group
  membership is addressed by path, so a move drops the old entry from
  all groups and does not auto-add the new path. Document this
  explicitly; consider a `sys/asset-group/remap` admin tool later.
- **Delete of a member's target** — the write-through handler detects
  a member whose target no longer exists and prunes it from all groups
  containing it, including the reverse index. A soft-deleted KV-v2
  version does *not* count as deletion; destroyed versions *do*.

### 5. Ownership and editability

Two-tier edit model:

- **Asset group owner** (the creator's `entity_id`, populated via
  per-user-scoping's `EntityStore`) has full CRUD on the group
  including membership edits.
- **Admins** (callers holding a policy with `manage` capability on
  `sys/asset-group/*`) can edit any group, including transferring
  ownership. An admin capability is required to delete a group whose
  owner is not the caller.
- End users with only read access on a group's underlying objects can
  *view* the group (name, description, the subset of members they can
  themselves read). Members they do not have access to are redacted
  from the membership list — present but labeled `<hidden>` so the
  group's size is accurate without leaking paths they cannot see.

### 6. API surface (all under `v2/` per agent.md)

CRUD:

| Method | Path                                                    | Purpose |
|--------|---------------------------------------------------------|---------|
| LIST   | `/v2/asset-groups`                                      | List all group names the caller can see |
| GET    | `/v2/asset-groups/{name}`                               | Read a group (membership redacted as above) |
| PUT    | `/v2/asset-groups/{name}`                               | Create or replace (partial updates merge; members list replaces wholesale) |
| DELETE | `/v2/asset-groups/{name}`                               | Delete a group (owner or admin) |

Membership (fine-grained):

| Method | Path                                                              | Purpose |
|--------|-------------------------------------------------------------------|---------|
| POST   | `/v2/asset-groups/{name}/members`                                 | Add one or more members (idempotent) |
| DELETE | `/v2/asset-groups/{name}/members/{kind}/{path}`                   | Remove a single member |

Reverse-lookup:

| Method | Path                                                              | Purpose |
|--------|-------------------------------------------------------------------|---------|
| GET    | `/v2/asset-groups/by-secret/{path}`                               | List groups a KV path belongs to |
| GET    | `/v2/asset-groups/by-resource/{name}`                             | List groups a resource belongs to |

Admin:

| Method | Path                                                              | Purpose |
|--------|-------------------------------------------------------------------|---------|
| POST   | `/v2/asset-groups/{name}/transfer`                                | Transfer ownership to another entity (admin-only) |
| POST   | `/v2/sys/asset-group-reindex`                                     | Rebuild reverse indexes from primary records (admin-only) |

History:

| Method | Path                                                              | Purpose |
|--------|-------------------------------------------------------------------|---------|
| GET    | `/v2/asset-groups/{name}/history`                                 | Change history (before/after membership diffs), mirroring identity-group history |

### 7. GUI

Three integration points:

1. **New "Groups" page under Organization** — list, create, edit,
   delete asset groups. The editor shows two panels: a secret picker
   (tree, matches the SecretsPage browser) and a resource picker
   (list, matches ResourcesPage). Adds/removes are staged and committed
   on Save. Membership chips in the header show the per-kind counts.
2. **Group chips on object pages.** Each secret row in SecretsPage
   and each resource row in ResourcesPage shows a line of chips for
   the asset groups it belongs to. Clicking a chip filters the list.
   Right-click or a menu offers "Add to group..." / "Remove from
   group...".
3. **Sidebar filter.** SecretsPage and ResourcesPage gain a "Group"
   filter dropdown that scopes the list to a single group.

The existing Identity Groups page (`/groups`) renames visually to
**Identity Groups** to disambiguate from the new Asset Groups page,
which lives at `/asset-groups`. Route and backend name stay
`/groups` to avoid a breaking rename.

### 8. Sharing interaction (future, from per-user-scoping)

Once `SecretShare` lands, an asset group becomes a valid share target:
one share record against the group name grants the listed capabilities
to the grantee for every current and future member of that group. This
is the primary ergonomic reason to ship asset groups before
per-user-scoping's sharing phase.

Share semantics on asset groups:

- A share on `asset-group:<name>` expands at authorize time to the
  member set via the reverse index.
- Removing a member from a group implicitly revokes the share's reach
  for that member; the `SecretShare` record itself is unchanged.
- Deleting the group fans out: all shares that target it are removed.

## Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | `AssetGroupStore` + CRUD + reverse indexes under the system barrier | Done (`src/modules/resource_group/group_store.rs`; two reverse indexes — resource-name and canonicalized KV-path) |
| 2 | `v2/` CRUD + membership + reverse-lookup API | Done (HTTP + Tauri: `list` / `read` / `write` / `delete` + `by-resource` / `by-secret` + `reindex` + `history`) |
| 3 | Change history (before/after member diffs) | Done (mirror of identity-group history; newest-first) |
| 4 | ACL grammar extension (`groups` qualifier) + evaluator integration | Done (resource half + KV half via secret-index; compile-time warning on unknown group references) |
| 5 | List-filter path for `list` operations using the reverse index | Done (narrows LIST response keys when list was authorized via a `groups = [...]` rule) |
| 6 | Lifecycle hooks: prune group membership on target delete/destroy | Done (resource-delete in the resource module; KV-delete via `PolicyStore::post_route`) |
| 7 | GUI: Asset Groups page, chips on objects, sidebar filter | Done (Termius-style group cards on Resources and Secrets pages with click-to-filter + breadcrumb; collapsible admin menu) |
| 8 | Admin ownership-transfer + reindex endpoints and GUI | Done (`POST /v2/sys/asset-group-owner/transfer`; `reindex` is the recovery path for torn writes) |
| 9 | Sharing integration (gated on per-user-scoping phase 8) | Done (`ShareTargetKind::AssetGroup`; indirect resolution expands shares to the member set at authorize time; member redaction for non-owner / non-admin readers) |

All nine phases shipped. The implementation lives under
`src/modules/resource_group/` (the module name kept the original
"resource-group" label for backward compatibility; the operator-facing
label is "Group").

## Testing Plan

- **Unit**: group CRUD (name validation, member canonicalization,
  deduping), reverse-index maintenance across add/remove/delete-target.
- **Authorization**: matrix of `{groups present, scopes present,
  both present, neither present} × {member, non-member} × {owner,
  non-owner, shared, not-shared} × {create/read/update/delete/list}`.
- **List-filter**: a caller whose policy grants read via `groups =
  ["alpha"]` listing `resources/` sees only the alpha-group members.
- **Regression**: an untouched policy (no `groups` qualifier) continues
  to exhibit literal-string behavior. All existing tests pass without
  modification.
- **Consistency**: kill the process mid-write between the primary
  record and reverse index. On restart, `sys/asset-group-reindex`
  restores the index from primary records.

## Open Questions

- **Nested groups.** Should an asset group be able to contain another
  asset group? Keeps membership clean but makes the reverse index
  recursive. Proposed v1 answer: **no**; revisit if ergonomics demand
  it.
- **Cross-mount secrets.** KV paths in members are mount-qualified. If
  an operator remounts KV at a different path, memberships break. A
  per-mount alias table could decouple this; out of scope for v1.
- **Membership cardinality.** The reverse index assumes each object is
  in a small number of groups (≤ ~20). Large objects-per-group are
  fine; many groups per object is the expensive direction. Add a soft
  per-object cap (32 groups?) with a clear error.
- **Policy referencing a non-existent group.** Proposed: policy-compile
  warns but the policy is accepted; the unknown group contributes no
  authorization. A later group creation retroactively activates the
  clause. Document explicitly.
- **Interaction with identity groups.** An identity group can attach
  policies; those policies may reference asset groups via `groups =
  [...]`. This is the clean composition path — no new "identity group
  ↔ asset group" relation needed.

## Current State

- **Resource half: shipped** as [Resource Groups](resource-groups.md).
  Covers phases 1–3 (store + member-index + CRUD + history), the
  resource-half of phase 4 (ACL `groups = [...]` qualifier + evaluator
  integration), and phase 6 (resource-delete lifecycle prune). A
  `path "resources/resources/*" { groups = [...] capabilities = [...] }`
  policy rule is enforced per-request via the member-index.
- **KV-secret half: shipped.** `ResourceGroupEntry` grew a
  `secrets: Vec<String>` field stored in canonical form (the KV-v2
  `data/` / `metadata/` segments are stripped so all three variants
  of the same logical path collapse to one entry). A parallel
  `sys/resource-group/secret-index/<base64url(path)>` reverse index
  lets `groups_for_secret(path)` run in a single read. The HTTP API
  grew a `GET /by-secret/<b64url_path>` reverse-lookup route; the
  group-write payload accepts a `secrets` comma-string or array.
  `PolicyStore::post_auth` resolves KV candidate paths (anything not
  under the fixed `sys/`/`auth/`/…/`resources/` prefixes) into the
  secret-index and unions the result with the resource-index into
  `Request::asset_groups`, so the same `groups = [...]` qualifier
  gates KV paths exactly the way it gates resource paths.
- **KV-delete lifecycle hook: shipped.** `PolicyStore` now implements
  `Handler` in addition to `AuthHandler`. Its `post_route` runs after
  the backend returns with the full pre-strip request path and, for
  KV paths (anything outside the fixed non-KV prefix list), calls
  `ResourceGroupStore::prune_secret`. Failures are logged; they do
  not fail the delete.
- **List-filter: shipped.** `ACL::allow_operation` records a
  `list_filter_groups` set when a LIST op is only authorized via a
  `groups = [...]`-gated rule; `post_auth` copies it onto the request;
  `post_route` filters the response `keys` to entries whose full path
  resolves to any of those groups. Ungated list grants defeat the
  filter so a user's broader access is never accidentally narrowed.
- **Policy-compile warning: shipped.** Writing a policy whose
  `groups = [...]` clause references an unknown group returns a
  response warning listing the unknown names. The write succeeds —
  creating a matching group later retroactively activates the clause.
- **Ownership, admin transfer, sharing: design only.**
  `owner_entity_id`, the two-tier edit model, the admin
  ownership-transfer endpoint, `<hidden>` membership redaction for
  unreadable members, and `SecretShare` integration are all still
  unimplemented. Per-user-scoping (`scopes = [...]`) is the
  dependency for most of those; the two features compose (`groups`
  and `scopes` OR together on a single rule).
- **GUI: design only.** No Asset Groups / Resource Groups page, no
  chips on object pages, no sidebar filter.
