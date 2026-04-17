# Identity Groups

Status: Backend + HTTP API **Done**. GUI integration **Pending**.

## Goal

Add a flat grouping layer that sits between auth backends and the policy
subsystem. A **user group** holds a list of UserPass usernames; an
**application group** holds a list of AppRole role names. Each group also
carries a list of policy names. At login time, policies attached to any group
the caller belongs to are unioned with the caller's directly-attached
policies.

## Why not a full Vault-style entity/identity layer

BastionVault's auth model today is backend-centric and flat: each backend
(UserPass, AppRole, Token, Cert, FIDO2) stores its own principals with
directly-attached policies. Modeling full Vault-style entities with aliases
across backends is a much larger lift. Groups give operators the key
ergonomic win — "add all platform engineers to one group, then change the
policy in one place" — without touching the rest of the identity model.

Trade-off: a single human who logs in via UserPass *and* OIDC (future) will
need to be added to a user group once per backend. That is acceptable for v1.

## Design

### Data model

```
GroupEntry {
    name:        String,
    description: String,
    members:     Vec<String>,   // usernames or role names
    policies:    Vec<String>,   // policy names
    created_at:  RFC3339 String,
    updated_at:  RFC3339 String,
}
```

Two kinds: `User`, `App`. Names are lowercased and must not contain `/` or
`..`. Members and policies are trimmed, de-duplicated, and empties dropped.

### Storage

All data is encrypted behind the vault barrier via the system view. Physical
keys:

```
sys/identity/group/user/{group_name}   -> GroupEntry
sys/identity/group/app/{group_name}    -> GroupEntry
```

No new physical table; all data is a JSON blob encrypted with
`ChaCha20-Poly1305` (same barrier as policies, users, AppRoles).

### Module wiring

- `src/modules/identity/group_store.rs` — `GroupStore` owns two `BarrierView`
  sub-views, exposes CRUD + `expand_policies(kind, member, direct)`.
- `src/modules/identity/mod.rs` — `IdentityModule` registers a logical
  backend factory at `setup()` time so the `identity/` mount binds on first
  unseal. The `GroupStore` is created in `init()` (which runs after unseal)
  and exposed via an `ArcSwap<Option<Arc<GroupStore>>>`. Handlers resolve the
  store lazily via the module manager.
- `src/mount.rs` — the `identity/` mount is added to `DEFAULT_CORE_MOUNTS`
  for new deployments. `mount_update()` injects any missing default core
  mounts without overwriting existing entries, so upgrading deployments pick
  up the mount on their next unseal.

### HTTP API

Mounted at `identity/`. Routes:

| Method | Path | Purpose |
|--------|------|---------|
| LIST   | `/v1/identity/group/user`          | List user group names |
| GET    | `/v1/identity/group/user/{name}`   | Read a user group |
| PUT    | `/v1/identity/group/user/{name}`   | Create or update (partial updates preserve unspecified fields) |
| DELETE | `/v1/identity/group/user/{name}`   | Delete a user group |
| LIST   | `/v1/identity/group/app`           | List application group names |
| GET    | `/v1/identity/group/app/{name}`    | Read an application group |
| PUT    | `/v1/identity/group/app/{name}`    | Create or update |
| DELETE | `/v1/identity/group/app/{name}`    | Delete an application group |

Write-payload fields: `description` (string), `members` (comma-separated
string or array of strings), `policies` (comma-separated string or array of
strings).

### Policy resolution at login

- **UserPass** (`src/modules/credential/userpass/path_login.rs`): after
  loading the `UserEntry`, the login handler calls
  `expand_identity_group_policies(GroupKind::User, username, &user.policies)`
  and uses the unioned set for both `auth.policies` and `token_policies`.
  Token renewal compares against the unioned set, so adding or removing a
  user from a group takes effect on the next renewal.
- **AppRole** (`src/modules/credential/approle/path_login.rs`): the login
  handler clones `role_entry`, replaces `token_policies` with the unioned
  set via `expand_identity_group_policies(GroupKind::App, role_name, ...)`,
  then calls `populate_token_auth`.
- On any expansion error (module absent, store unavailable, I/O error), both
  login paths fall back to the caller's direct policies and log a warning.
  Login is never blocked by an identity-subsystem failure.

### Implementation notes

- Group enumeration at login time is a linear scan over the relevant kind's
  keyspace. Expected cardinality is small (tens to low hundreds). If this
  becomes a hotspot, a reverse member-index (`sys/identity/member-index/...`)
  can be added without changing the API.
- Group names are case-insensitive (lowercased on write); member comparisons
  are also case-insensitive.
- The backend enforces no limits on group size or policy count; policy
  validation is delegated to the existing policy subsystem at evaluation
  time (missing policies are silently dropped by `PolicyStore::new_acl`).

## Phases

| Phase | Description | Status |
|-------|-------------|--------|
| 1 | `GroupStore` + `IdentityModule` + logical backend | Done |
| 2 | HTTP API under `identity/` with list/read/write/delete | Done |
| 3 | Default mount + migration in `mount_update` | Done |
| 4 | UserPass + AppRole login policy union | Done |
| 5 | Integration tests (CRUD, namespace isolation, end-to-end login) | Done |
| 6 | GUI: Groups page, members/policies editors, Tauri commands | Pending |
| 7 | Extension to other auth backends (Certificate, OIDC, SAML) | Pending |

## Testing

Three integration tests in `src/modules/identity/mod.rs`:

1. `test_identity_user_group_crud` — create/read/list/update/delete, partial
   update preserves unspecified fields.
2. `test_identity_app_group_isolated_from_user_group` — app groups do not
   appear in user-group listings and vice versa.
3. `test_identity_group_policy_expansion_at_login` — end-to-end: a user
   logs in, is denied a path, is added to a group granting the path, logs
   in again, and succeeds.

## Current State

Phases 1–5 shipped in the initial change. GUI integration (Phase 6) and
extension to the Certificate/OIDC/SAML auth backends (Phase 7) are pending.
