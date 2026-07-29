# Feature: Self-Service Profile (own password / contact / default accounts)

## Summary

A signed-in operator can maintain their own account without an
administrator: change their **password** (when the login was
username/password), edit their **contact details** (email / phone), and set
their **default resource accounts** — the per-OS login names used by
`default-account` connection profiles, including the optional stored Windows
RDP password.

All of it lives behind three v2 `sys/` routes plus a write op on the existing
`default-account/self` route, and one new GUI page (**My Profile**, reachable
from the sidebar footer). Every endpoint resolves the calling principal from
the request token: none of them accept a username, so none can reach another
operator's record.

## Motivation

- **Password rotation was admin-only.** Before this, the only way to change a
  password was `POST auth/<mount>/users/<name>` or
  `.../users/<name>/password`, both of which require a policy that can write
  *any* user — i.e. an administrator. A user who suspected their password was
  exposed had to file a ticket, and the resulting password was known to
  whoever typed it.
- **Contact details were admin-only too**, for the same reason, so they drifted
  stale exactly when they matter (offboarding, incident follow-up).
- **Default resource accounts are inherently personal.** The record says "this
  is the login name *I* use on target hosts" — see
  `features/default-resource-account.md`. It shipped editable only from the
  admin Users page (an explicitly listed follow-up in that spec), which is the
  wrong owner for the data.

## Design

### Where the routes live, and why not on the userpass mount

The natural home for "change my password" is the userpass backend, but the ACL
is exact-path and a userpass backend can be mounted anywhere (`auth/userpass/`,
`auth/pass/`, …). A rule in a built-in policy cannot name a mount-relative
route without guessing the mount name, so a self-service route there could not
be granted once for every deployment.

The `sys/identity/…/self` paths are stable regardless of where the credential
backend is mounted. `DEFAULT_POLICY` — which every login token carries, since
`sanitize_policies` always appends `default` unless `no_default_policy` is set
— grants them once. This mirrors the existing `sys/identity/default-account/self`
precedent.

### Resolving the caller's principal

Two different resolutions, because the two stores are keyed differently:

- **The userpass record** (password, email, phone) is found through the
  token's own login path. `TokenEntry::path` is `auth/<mount>/login/<user>`,
  so `Router::matching_mount` recovers the **real** auth mount. This matters:
  every userpass mount stamps the literal `userpass/` into `mount_path` token
  metadata, so metadata alone cannot tell two userpass mounts apart, and
  guessing wrong would let one mount's `alice` rewrite the other's record. The
  mount's `logical_type` is checked to be `userpass` before anything is read.
- **The default-account record** is keyed on the identity-layer
  `(mount, name)` principal, so it reuses the same candidate resolution the
  `self` read already used — `mount_path` + `username` first, then every alias
  on the caller's entity (covering AppRole / OIDC / SAML / cert logins).
  Factored out of `handle_default_account_self` into
  `self_default_account_candidates` / `self_default_account`.

A token that was not minted by a userpass mount (root tokens,
`auth/token/create` children, AppRole, OIDC) has no password to change. The
profile read still succeeds — with `can_change_password = false` so the GUI
renders an explanation rather than an error — and the write endpoints refuse
with an explicit 400.

### Routes (v2-only, `src/modules/system/self_profile.rs`)

| Method | Path | Purpose |
|---|---|---|
| Read | `v2/sys/identity/profile/self` | Identity, capability flags, contact details, default accounts. |
| Write | `v2/sys/identity/profile/self/password` | `current_password` + `new_password`. |
| Write | `v2/sys/identity/profile/self/contact` | `email` / `phone`, write-preserve. |
| Read | `v2/sys/identity/default-account/self` | Unchanged (reveals the caller's own stored RDP password to the connect host). |
| **Write** | `v2/sys/identity/default-account/self` | **New.** Set your own per-OS accounts; every field write-preserve; response masked. |

HTTP shims are registered v2-only in `init_sys_service` (`src/http/sys.rs`),
siblings to `capabilities-self` / `default-account/self`. None of them are in
`root_paths` — they are caller-scoped by construction, and a `profile/*`
root-path glob would make them unreachable for the users they exist for.

### Password-change rules

1. Token must come from a `userpass` mount → else 400.
2. Account not `disabled` (403) and not `fido2_enabled` (400 — nothing to
   change).
3. `new_password` at least **8 characters** and different from the current one
   → else 400. The desktop GUI additionally enforces the operator-configured
   password policy (`checkPasswordPolicy`) before it ever calls; the server
   floor exists so a self-service change can never weaken an account to
   something trivial, whatever the client.
4. `current_password` verified with bcrypt against the stored hash → else 403.
5. Rehash with `bcrypt::DEFAULT_COST` and read-modify-write the whole
   `UserEntry`, so policies, TTLs, MFA binding, and FIDO2 credentials are
   untouched.

### Security decisions worth reviewing

- **Re-authentication is mandatory.** Requiring the current password is the
  usual expectation for a self-service change, and it means a stolen or
  borrowed token is not by itself enough to lock the real operator out of
  their account.
- **A wrong current password does not feed the lockout counter.** Doing so
  would hand anyone with a live token a reliable way to deny the account to
  its owner. The caller is already authenticated, so the counter buys little;
  the attempt is written to the user-audit trail instead (op `password-change`,
  `details` = "self-service; refused: …"), and the IP-level DoS guard
  (`src/dos/`) still throttles the request rate.
- **Sessions are not revoked on password change.** There is no per-principal
  lease index to revoke by — `revoke-prefix` on `auth/<mount>/login/` would
  kill every user on the mount. Tokens issued before the change keep working
  until they expire; the GUI says so in the success toast. Revoking them is an
  administrator action.
- **The stored Windows RDP password is never echoed.** The self *write*
  responds with `has_windows_password` only, exactly like the admin read. The
  `self` read remains the single path that returns the plaintext, and only to
  its own owner (the Tauri command strips it before it reaches the frontend —
  only the connect host, in Rust, consumes it).
- **Contact fields stay informational.** Unchanged from
  `features/userpass-account-security.md`: never an auth factor, never used
  for notifications, magic links, or account recovery. Making them
  self-editable therefore adds no recovery-path attack surface. The same
  permissive `is_plausible_email` typo check applies.

### Policy grants

Added to `DEFAULT_POLICY`, the implicit `NAMESPACE_SELF_POLICY` (so
namespace-bound tokens, whose named policies resolve from an initially-empty
tenant keyspace, are covered too), and the three general user baselines
`standard-user`, `standard-user-readonly`, and `secret-author`, which each
mirror the default policy's self-service block:

```hcl
path "sys/identity/profile/self"          { capabilities = ["read"] }
path "sys/identity/profile/self/password" { capabilities = ["update"] }
path "sys/identity/profile/self/contact"  { capabilities = ["update"] }
path "sys/identity/default-account/self"  { capabilities = ["read", "update"] }
```

The admin `default-account/{mount}/{name}` route is deliberately *not* granted
— that one reaches other people's records and still needs an operator policy.
The engine add-on policies (`pki-user`, `totp-user`, `transit-user`,
`ldap-user`, …) are unchanged: they layer on top of a baseline, and every
login token carries `default` regardless.

Note that the `read` on `default-account/self` also closes a latent gap: the
`default-account` connect path reads it with the *caller's* token, so a
`standard-user` launching such a profile previously depended on `default`
carrying no grant for it at all.

### GUI

- **`gui/src/routes/ProfilePage.tsx`** — "My Profile", three independently
  saved cards (contact / password / default resource accounts) plus a
  read-only identity summary. Each card saves on its own so a failure in one
  does not roll back another. The password card renders an explanation instead
  of a dead form when `can_change_password` is false, distinguishing FIDO2-only,
  disabled, and non-password logins.
- **Route** `/profile` in `App.tsx`, deliberately not under `/settings` —
  Settings is server-level operator configuration; this page only ever touches
  the signed-in user's own account.
- **Entry point**: the sidebar footer, labelled with the operator's login name,
  next to Sign Out. Visible to every authenticated user; there is nothing to
  gate on policy because the endpoints behind it are caller-scoped.
- **Tauri commands** in `gui/src-tauri/src/commands/profile.rs`
  (`get_my_profile`, `change_my_password`, `update_my_contact`,
  `set_my_default_account`) with `api.ts` wrappers. Kept separate from
  `commands/users.rs`, which is the admin surface and uses a root token.

## Scope

- **In scope:** own password (userpass), own email / phone, own per-OS default
  resource accounts + stored Windows RDP password; a GUI page and its entry
  point; policy grants; audit-trail entries.
- **Out of scope (future):**
  - Self-service FIDO2 key enrolment / removal (still admin-driven from the
    Users page).
  - Self-service TOTP MFA enrolment — a user cannot today bind their own TOTP
    key; an admin sets `totp_key`.
  - Revoking a principal's other sessions on password change (needs a
    per-principal lease index).
  - Self-service for non-userpass principals' passwords (AppRole secret-ids,
    LDAP, OIDC — those credentials live outside the vault or have their own
    rotation paths).
  - A server-enforced password policy. The composition policy
    (`min_length`, character classes) is a desktop-client preference today;
    the server enforces only the 8-character floor. Promoting it to a
    server-side mount config would apply to the admin write path too and is a
    separate change.

## Current State

**Done.** Backend handlers + route registration, v2 HTTP shims, policy grants,
Tauri commands, `api.ts` wrappers, the My Profile page and its sidebar entry,
and tests all shipped.

| Phase | Status |
|---|---|
| Backend: `profile/self` read + `password` + `contact` writes | Done |
| Backend: `default-account/self` write (caller-scoped, write-preserve) | Done |
| v2 HTTP shims (`src/http/sys.rs`) | Done |
| Policy grants (`default`, `namespace-self`, three user baselines) | Done |
| Tauri commands + `api.ts` wrappers | Done |
| GUI: My Profile page + sidebar entry | Done |
| Tests (Rust HTTP roundtrip + caller-scoping; GUI vitest) | Done |

### Tests

- `src/http/sys.rs::self_profile_route_tests` — full roundtrip driven over the
  real HTTP pipeline with a **non-root** userpass token (which also proves the
  `default` policy grant): profile read reports the real issuing mount,
  contact write-preserve, email validation, default-account write-preserve +
  password masking, agreement with the admin read of the same record, wrong /
  short / correct password changes with re-login checks, and policy
  preservation. A second test proves caller scoping (bob's change does not
  touch alice) and the non-userpass token behaviour.
- Email validation is not re-implemented: the self route calls the userpass
  backend's own `is_plausible_email` (now `pub(crate)`), so an address an admin
  may store for a user is exactly one the user may store for themselves, and
  the existing `path_users::tests` cover both.
- `gui/src/test/selfProfile.test.tsx` — API wrapper argument shapes plus 9
  page-level tests (dirty-tracking, current-password gating, confirmation
  mismatch, password preserve vs clear, and both `can_change_password = false`
  explanations).
