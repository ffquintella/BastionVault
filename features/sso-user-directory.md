# Feature: SSO User Directory

## Summary

Every successful OIDC or SAML login upserts one passwordless record for the
principal the login was decided for. The GUI's **Users** page lists those
records on an **SSO Users** tab, beside the userpass accounts, so an operator
can see who has signed in through an identity provider, set the namespaces
each may sign in to, set a contact e-mail, and share resources with them.

## Current State

**Phase 1 (T555) — done with caveats.** Store, login wiring, `v2/sys/sso/users`
routes, GUI tab and tests landed together. Not yet exercised against a live
IdP: the login side is proven by unit tests of the record each callback builds
and by whole-vault route tests that seed the record the callback writes.
Remaining gaps are listed under "Not implemented".

## Motivation

An OIDC or SAML user had no presence in BastionVault until an admin knew their
exact principal name: they did not appear on the Users page, and — because the
SSO callbacks issued tokens without an `entity_id` — a share granted to them
never applied. An operator who saw `felipe.quintella@fgv.br` sign in had no way
to find that user, restrict their namespaces or share a resource with them.

## Design

### Record and storage

`crates/bv-auth-audit/src/sso_users.rs` (the crate both SSO backends and the
kernel already depend on, so no new dependency edge):

| Key | Value |
|---|---|
| `sys/sso-users/<hex(mount)>-<hex(username)>` | `SsoUserRecord` JSON, barrier-encrypted |

Hex keys map any principal name an IdP can produce (an e-mail address, a NameID
URI, a name containing `/`) to one flat storage key; hex digits never contain
`-`, so the separator cannot be forged. Fields: `version`, `username`, `mount`
(`oidc/` or `saml/`, the same key `NsAssignmentStore` and the entity alias
use), `auth_method`, `role`, `subject`, `email`, `email_source`
(`none`/`idp`/`admin`), `first_login`, `last_login`, `login_count`.

Persisted format: `version` 1. Every field after `username` and `mount` is
`#[serde(default)]`. A record whose `version` is newer than the running build
is read but never overwritten (an older binary would drop fields it does not
know); the login still succeeds and the refusal is logged.

### Login path

After `enforce_login_assignment` has accepted the login, each callback:

1. resolves or creates the principal's identity entity
   (`ensure_sso_entity`: `IdentityService::entity_id_for_alias`, then the
   namespace `max_entities` check, then `ensure_entity_id`) and stamps
   `entity_id` on the token — the key shares and owner-scoped rules use;
2. upserts the directory record (`record_sso_login`).

Neither step can refuse the login. The decision is unchanged: the IdP's signed
answer, the role, `bound_*` checks and the namespace assignment decide it, as
before. A storage failure is logged at `ERROR` (target `sso`, mount and error
only — no principal name, no claim, no token). An exhausted `max_entities`
quota issues the token without `entity_id` (a `WARN`) instead of refusing, so
the quota cannot become an authentication decision for SSO principals.

E-mail: OIDC takes the standard `email` claim unless `email_verified` is
false; SAML takes the role's `email` mapping, then a well-known attribute
(`email`, `mail`, `emailaddress`, the `urn:oid:0.9.2342.19200300.100.1.3` and
WS-Federation URIs), then an `emailAddress`-format NameID. An address an admin
set is never overwritten by a login.

An empty name, the `(unknown)` placeholder, a name with surrounding whitespace
or control characters, or one longer than 512 bytes never becomes a record.
When an existing record's `subject` differs from the login's, a `security`
`WARN` names the mount only: the IdP re-keyed the user or the role's
`user_claim` is not unique.

### API

`v2` only, root namespace only (a namespace header is refused with `400`),
plain ACL like `auth/<mount>/users-info`. See `docs/api.md` § SSO User
Directory.

| Path | Ops |
|---|---|
| `sys/sso/users` | `list`, `read`: `{ keys, records, total }` |
| `sys/sso/users/{oidc\|saml}/{name}` | `read`; `update` (`email` only, existing records only); `delete` |

Namespace access reuses `sys/identity/ns-assignment/{mount}/{name}`; no second
mechanism. `DELETE` removes the record only: the assignment (removing it would
widen where the principal may sign in) and the entity (shares stay attached)
are kept. Admin edits and removals are written to the user-audit trail.

### GUI

`gui/src/routes/UsersPage.tsx` gains two tabs: **Users** (the userpass list and
Account Security card, unchanged) and **SSO Users**
(`gui/src/components/users/SsoUsersTab.tsx`, loaded only when opened). Rows
show an `SSO` badge, provider and role, e-mail and last login; there is no
password or FIDO2 control. The edit dialog shows provider, subject and login
times, the shared namespace chips (`NamespaceAccessSelector`, also used by the
userpass dialogs) and the e-mail. If the current assignment cannot be read the
dialog says so and does not write one — an empty write would clear it.

### Policies

SSO users' policies still come from the role. Identity-group policy expansion
is not applied on OIDC/SAML logins (it is on userpass); adding it changes the
authorization of every SSO token and the renewal policy-drift check, so it is a
separate decision, not part of this feature.

## Not implemented

- Group-derived policies for SSO users (see Policies).
- Pre-registering an SSO user before their first login; writes edit existing
  records only.
- Pagination of `sys/sso/users`; the listing is one bulk read.
- Per-mount keys: both backends stamp the literal `oidc/` / `saml/` as
  `mount_path`, so two OIDC mounts share one key space, exactly as their
  namespace assignments already do.
- `login_count` is read-modify-write without a storage lock; two concurrent
  logins of the same principal may undercount it by one.

## Key Reference Files

- `crates/bv-auth-audit/src/sso_users.rs` — store, `SsoLogin`, `ensure_sso_entity`
- `crates/bv-auth-oidc/src/path_callback.rs`, `crates/bv-auth-saml/src/path_callback.rs` — login wiring
- `crates/bv-kernel/src/modules/system/sso_users.rs` — `sys/sso/users` handlers and route tests
- `crates/bv-server/src/sys.rs`, `crates/bv-server/src/sys/routes.rs` — `/v2/sys/sso/users` shims
- `gui/src/components/users/SsoUsersTab.tsx`, `gui/src-tauri/src/commands/users.rs` — GUI
