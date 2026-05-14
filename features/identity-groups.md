# Identity Groups

Status: Backend + HTTP API **Done**. GUI integration **Done**. FIDO2 login
policy union **Done**. Cert/OIDC/SAML extension deferred until those
backends are themselves implemented.

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
| LIST   | `/v1/identity/group/user`                  | List user group names |
| GET    | `/v1/identity/group/user/{name}`           | Read a user group |
| PUT    | `/v1/identity/group/user/{name}`           | Create or update (partial updates preserve unspecified fields) |
| DELETE | `/v1/identity/group/user/{name}`           | Delete a user group |
| GET    | `/v1/identity/group/user/{name}/history`   | Read change history for a user group (newest first) |
| LIST   | `/v1/identity/group/app`                   | List application group names |
| GET    | `/v1/identity/group/app/{name}`            | Read an application group |
| PUT    | `/v1/identity/group/app/{name}`            | Create or update |
| DELETE | `/v1/identity/group/app/{name}`            | Delete an application group |
| GET    | `/v1/identity/group/app/{name}/history`    | Read change history for an application group |

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
- **FIDO2** (`src/modules/credential/userpass/path_fido2_login.rs` and the
  legacy standalone backend at `src/modules/credential/fido2/path_login.rs`):
  both FIDO2 login-complete handlers call the same
  `expand_identity_group_policies(GroupKind::User, username, ...)` used by
  password login, so a user in a user-group receives the same policies
  whether they authenticate with a password or a passkey. Token renewal in
  the unified userpass path reuses `login_renew`, which already expands
  against the current group membership.
- On any expansion error (module absent, store unavailable, I/O error), all
  login paths fall back to the caller's direct policies and log a warning.
  Login is never blocked by an identity-subsystem failure.

### Change history

Every create/update/delete is appended as a `GroupHistoryEntry` under
`sys/identity/group-history/{user,app}/{name}/<20-digit-nanos>`:

```
GroupHistoryEntry {
    ts:             RFC3339 timestamp,
    user:           caller username (auth.metadata.username, falls back to
                    auth.display_name, then "unknown"),
    op:             "create" | "update" | "delete",
    changed_fields: Vec<String>,         // subset of: description, members, policies
    before:         Map<String, Value>,  // prior values for those fields
    after:          Map<String, Value>,  // new values for those fields
}
```

`changed_fields` is the list of top-level fields whose value differs from
the previous stored entry. `before` and `after` carry the actual values
of exactly those fields (`description` as a JSON string; `members` and
`policies` as JSON arrays of strings) so audit consumers can reconstruct
prior states and the GUI can render precise "added X, removed Y" diffs
for membership and policy changes.

`members` and `policies` are compared as sets, so reordering alone does
not record a new entry. A write that does not change anything (no-op
save) is suppressed to avoid log noise; the initial create is always
recorded even with empty payload. For a `create` entry `before` is empty;
for `delete` entries `after` is empty and `before` retains the full
final state so the record is self-contained.

History is retained when the group itself is deleted so the audit trail
remains available. There is no automatic retention cap; operators who
want one can purge entries by listing and deleting under the history
prefix out-of-band.

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
| 6 | GUI: Groups page, members/policies editors, Tauri commands | Done |
| 7 | FIDO2 login policy union (shares UserPass username namespace) | Done |
| 8 | Extension to Certificate / OIDC / SAML when those backends land | Deferred |

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

Phases 1–7 shipped: CRUD, HTTP API, default mount, UserPass/AppRole login
union, integration tests, GUI, and FIDO2 login union. Phase 8 (extension
to Certificate/OIDC/SAML) is deferred — the Certificate backend is
currently disabled in the OpenSSL-free build and the OIDC/SAML backends
are design-only. When those backends are implemented they should call
`expand_identity_group_policies(GroupKind::User, user_id, &policies)`
using whatever stable identifier the IdP provides (subject/nameID, mapped
to a user-group member string on the backend side).

### FIDO2 integration note

Testing FIDO2 login end-to-end requires a real WebAuthn authenticator, so
no new integration test was added for the FIDO2 wiring specifically. The
underlying `GroupStore::expand_policies(GroupKind::User, ...)` call is
exercised by `test_identity_group_policy_expansion_at_login`, and the
FIDO2 login handlers now invoke the same helper used by UserPass password
login — so if the UserPass test passes, FIDO2 logins for the same
username receive the same unioned policy set.

### Phase 6 (GUI) details

- Tauri commands in `gui/src-tauri/src/commands/groups.rs`: `list_groups`,
  `read_group`, `write_group`, `delete_group`. All accept a `kind` argument
  (`"user"` or `"app"`), delegate to the `identity/` logical mount, and
  marshal members/policies as comma-separated strings on the wire.
- Route `/groups` renders `GroupsPage` with a tab switcher between user
  and application groups, a left-rail group list, and a detail card
  showing members, policies, timestamps, and edit/delete actions.
- The create/edit modal populates multi-select chips for members from the
  current UserPass or AppRole mount and for policies from the policy
  subsystem. A free-form comma-separated input allows adding members that
  do not live in the currently-enumerated mount.
- When `identity/` is not yet mounted (older deployments pre-unseal), the
  page shows a neutral empty state pointing the operator at
  reseal/unseal to pick up the default-mount migration.

## Phase 7: Group-shared resources

**Status:** Done (server + GUI + docs).

Identity groups now double as share targets. A share's `grantee_kind`
field selects between an entity grantee (UUID; the legacy default) and
a group grantee (lowercased group name, kind = `group_user` or
`group_app`). Group shares are *informational + gated*: a share that
points at group `engineering` is visible to every member of that group
in the "Shared with me" tab **only when** the caller carries at least
one policy whose `metadata.group_shared_resources` is `"true"`. The
share itself does not grant ACL capability — the caller's regular
policies still own the access decision; the share row simply surfaces
the target on the caller's per-user shared list.

### Why intersection, not union

The simplest design ("group share === policy attached to every
member") risks privilege escalation when group membership churns: an
admin adds a user to `engineering` and the user instantly gets `update`
on every secret previously shared with the group. By treating group
shares as a *visibility filter* over the caller's existing policy
capabilities, membership changes never expand a user's effective ACL —
only the discoverable surface of "what is this group working on."
Operators who want capability-granting group shares should attach the
relevant policy to the group itself (`GroupEntry.policies`); the
login-time `expand_identity_group_policies` flow has unioned those
policies into the token since Phase 1.

### Wire format

```
identity/sharing/by-target/<kind>/<base64url(target)>/<grantee>
  body { target_kind, target_path, grantee_kind, capabilities, expires_at? }
```

- `grantee_kind = "entity"` (default for back-compat): `grantee` is an
  entity UUID; existing share rows continue to resolve unchanged.
- `grantee_kind = "group_user"` or `"group_app"`: `grantee` is the
  identity-group name (lowercased on write; case-insensitive match).

`identity/sharing/for-me` is a caller-introspecting LIST/READ endpoint
that returns a single payload:

```json
{
  "entity_id": "<resolved-via-alias-if-needed>",
  "group_shared_resources": true,
  "entries": [
    { "target_kind": "resource", "target_path": "teste1", "grantee_kind": "entity" },
    { "target_kind": "kv-secret", "target_path": "secret/eng/...", "grantee_kind": "group_user" }
  ]
}
```

`group_shared_resources` is `true` iff at least one of the caller's
attached policies carries the meta tag. The GUI's `SharingPage` reads
this flag to render a hint when the user is missing the policy meta
tag rather than silently dropping group entries.

### Sample HCL — opting a user into group shares

Attach a thin policy to anyone who should see group shares in their
"Shared with me" feed:

```hcl
# policies/group-shared-resources.hcl
name = "group-shared-resources"

metadata {
  group_shared_resources = "true"
}
```

That's it — no `path` blocks. The metadata is the entire point; access
to the underlying resources still flows through whatever policies the
user (or their groups) already carry.

### Sample HCL — full operator setup

```hcl
# policies/engineering.hcl — capability policy attached to the group
name = "engineering-shared"

path "resource/data/engineering/*" {
  capabilities = ["read", "list"]
}

path "secret/data/engineering/*" {
  capabilities = ["read", "list"]
}
```

```hcl
# policies/group-shared-resources.hcl — opt-in to seeing group shares
name = "group-shared-resources"

metadata {
  group_shared_resources = "true"
}
```

Wiring:

1. `identity/group/user/engineering` — group with members
   `["alice", "bob", "felipe2"]` and policies
   `["engineering-shared"]`. At login each member's token has the
   capability policy unioned in.
2. Attach `group-shared-resources` to each member (directly on the
   userpass user, or via a second group dedicated to the meta tag).
3. Admin grants `identity/sharing/by-target/resource/<b64>/engineering`
   with `grantee_kind = "group_user"`. The target shows up in
   `engineering`'s "Shared with me" feed without expanding any ACL.

Operators who want a *capability-granting* group share should attach
the capabilities to the group's policy list (step 1) — the share row
in step 3 then serves as the human-visible breadcrumb explaining *why*
those capabilities exist.
