# Per-User Scoping (Ownership & Sharing)

Status: **Design only.** Not yet implemented.

## Goal

Let operators grant narrowly-scoped access to end users based on
*ownership* rather than coarse path prefixes. Two concrete baseline
roles must be expressible:

1. **Read-only user** — can read (and list) secrets and resources they
   own, plus anything explicitly shared with them. Cannot create, update,
   or delete.
2. **Password administrator** — can create, read, update, delete, and
   (future) share secrets and resources *they created*, plus anything
   explicitly shared with them. Cannot touch items owned by other users
   unless they have been granted explicit access.

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

### 5. Sharing (future — sketch only)

Out of scope for the first implementation cut. Rough sketch only:

```
SecretShare {
    target_kind:     "kv-secret" | "resource",
    target_path:     "secret/data/foo" | "resources/server-01",
    grantee:         entity_id,
    granted_by:      entity_id,
    capabilities:    Vec<String>,    // subset of read, list, update, delete
    granted_at:      RFC3339,
    expires_at:      Option<RFC3339>,
}

sys/sharing/<target_hash>/<grantee_uuid>   -> SecretShare
sys/sharing-by-grantee/<grantee_uuid>/<target_hash> -> { target_kind, target_path }
```

Open sharing questions for the future doc:
- Can a sharee re-share? (Default: no.)
- Does `delete` propagate to shares? (Default: yes, share rows are
  cascaded on target delete.)
- GUI flow for sharing (resource-level vs secret-level).

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
# password-administrator
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

### 7. API surface (all under `v2/` per agent.md)

Ownership / sharing endpoints introduced by this feature:

| Method | Path                                                   | Purpose |
|--------|--------------------------------------------------------|---------|
| GET    | `/v2/sys/identity/entity/self`                         | Read the caller's own entity record |
| GET    | `/v2/sys/identity/entity/{id}`                         | Read an entity (privileged) |
| POST   | `/v2/sys/kv-owner/transfer`                            | Admin-only ownership transfer for a KV entry |
| POST   | `/v2/sys/resource-owner/transfer`                      | Same for a resource |
| PUT    | `/v2/sys/sharing/{target_hash}/{grantee}`              | Create a share (future phase) |
| GET    | `/v2/sys/sharing/by-grantee/{grantee}`                 | List what is shared *with* an entity (future) |
| DELETE | `/v2/sys/sharing/{target_hash}/{grantee}`              | Revoke a share (future) |

All existing `v1/` routes keep working unchanged. When an `owner`- or
`shared`-scoped policy rules a `v1/` path, authorization consults the
owner/share stores the same way.

## Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | `EntityStore`, auto-provision on first login, `auth.entity_id` plumbed into issued tokens | Pending |
| 2 | Policy templating (`{{username}}`, `{{entity.id}}`, `{{auth.mount}}`), `templated = true` honored | Pending |
| 3 | `scopes` qualifier in ACL grammar + evaluator; `any` scope backward-compatible | Pending |
| 4 | KV-secret owner store + write/delete hooks; list-filtering for `owner` scope | Pending |
| 5 | Resource `owner_entity_id` field + write/delete hooks; list-filtering | Pending |
| 6 | Seeded `standard-user-readonly` and `password-administrator` policies | Pending |
| 7 | GUI: show "owner" column on resources/secrets lists; "only show mine" toggle | Pending |
| 8 | Sharing MVP: `SecretShare` store + v2 API + evaluator hook | Pending |
| 9 | Sharing GUI: share dialog, "shared with me" section, revoke flow | Pending |
| 10 | Admin ownership-transfer endpoints + GUI | Pending |

Phases 1–6 deliver the two baseline roles the operator asked for.
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

Design approved in principle (this document). No code changes. The
currently-seeded `standard-user` policy (shipped in `e194fda`) remains
the broadly-scoped baseline until phase 6 replaces it with the two
ownership-aware policies described above.
