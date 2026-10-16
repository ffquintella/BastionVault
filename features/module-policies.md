# Feature: Module Policies

Per-module baseline policies an operator assigns by name, so that "what may
this person do with SSH (or PKI, or Resources …)" is a choice among four named
policies instead of hand-written HCL.

Source: `crates/bv-kernel/src/modules/policy/module_policies.rs`. Seeded by
`PolicyStore::load_default_acl_policy`.

## Current State

Done (T146). All 25 policies are seeded on unseal, the GUI nav gates name them,
and the ACL behaviour is unit-tested. Not yet exercised end-to-end against live
engine mounts.

| Phase | Scope | Status |
|---|---|---|
| 1 | Policy texts, seeding, ACL unit tests | Complete |
| 2 | GUI nav gates (`gui/src/lib/access.ts` `modulePolicies`) | Complete |
| 3 | Seed into namespace keyspaces for namespace-bound logins | Not planned (see below) |

## The variants

| Variant | Grants |
|---|---|
| `<module>-full` | Every operation on the module's mount (`create`, `read`, `update`, `delete`, `list`; `connect` for resources). |
| `<module>-read` | List and read. Never a write, never `connect`, never key or credential material. |
| `<module>-connect` | Use the module's targets without listing or reading what is behind them. |
| `<module>-shared` | Only what has been shared with the caller, directly or through an identity group they belong to (`metadata { group_shared_resources = "true" }`). |

`-connect` exists only where there is something to use, and `-shared` only
where the share store has a target kind for the module (`ShareTargetKind`:
kv-secret, resource, asset-group, file). A `pki-shared` would grant nothing.

| Module | Mount | Policies | `-connect` means | Not in `-read` |
|---|---|---|---|---|
| `secrets` | `secret/` | full, read, shared | — | — |
| `resource` | `resources/`, `resource-group/` | full, read, connect, shared | open a session (direct, web, or through Rustion) as the resource's credential, without `read` on `resources/secrets/*` | — |
| `files` | `files/` | full, read, shared | — | sync push, version restore |
| `ssh` | `ssh/` | full, read, connect | `sign/<role>`, `creds/<role>` (OTP), `lookup` | signed certs, OTPs |
| `pki` | `pki/` | full, read, connect | `issue/<role>`, `sign/<role>` (not `sign-verbatim`, which bypasses role constraints) | `cert/<s>/key`, `cert/<s>/export`, `issuer/<r>/export`, `key/<r>`, `keys`, `config/*` |
| `ad` | `openldap/` | full, read, connect | read `static-cred/<role>`, library check-out / check-in | `static-cred`, `config` (bind credential), `rotate-*` |
| `totp` | `totp/` | full, read, connect | read / validate `code/<key>` | codes |
| `transit` | `transit/` | full, read, connect | encrypt, decrypt, rewrap, sign, verify, hmac, datakey, random, hash | key lifecycle (`rotate`, `config`, `trim`, `import`) |

Every policy also carries the token self-service block (`lookup-self`,
`renew-self`, `revoke-self`, `audit-login`, `capabilities-self`,
`resultant-acl`) and the private cubbyhole, so it is usable on its own.

## "In that namespace"

Object rules are written as `{{request.namespace}}/<mount>/...`, the template
`shared-access` already uses. It resolves to the namespace the request is
addressed to, and to nothing at root (the separator is swallowed by
`substitute_path`). One policy stored at root therefore grants the module in
whichever namespace the holder is working in, and a request addressed to `dti/`
can only ever match `dti/<mount>/...`. Whether the holder may enter a namespace
is decided separately (`token_operable_resolved`); these policies do not confer
it.

Bare (un-templated) rules are limited to `sys/` / `auth/` self-service,
`cubbyhole/`, and the `rustion/` session endpoints, which are header-scoped
and never namespace-rewritten (`is_header_scoped_path`).

Mount names are the conventional ones above. A module mounted under another
name (`pki-corp/`) is not covered; grant that mount with a custom policy.

**Namespace-bound logins.** A token that logs in *to* a namespace resolves its
named policies from that namespace's own keyspace, which starts empty, so it
does not see these root policies. Operators who use namespace logins copy the
policy into the namespace (where the template still resolves to that
namespace). Seeding every namespace was considered and not done: it needs a
backfill of existing namespaces and per-namespace drift handling, and the
root-plus-template route covers the GUI's namespace picker, which is how
operators enter namespaces today.

## Why siblings repeat each other's path strings

ACL precedence picks a single governing ungated rule per request path; it
unions capabilities across policies only when the rule paths are identical
(`Permissions::merge`). If `pki-read` named `pki/roles/+` and `pki-full` named
only `pki/*`, a holder of both would be governed by the read rule on every role
and lose write. So:

- each `-full` restates, with full capabilities, every path its siblings name;
- `-read` and `-connect` use identical strings wherever they cover the same
  objects (e.g. both name `resources/secrets/*`, one with `read, list`, the
  other with `connect`, so holding both merges them).

`adding_a_variant_never_removes_access` checks every combination of a
module's policies, alongside `default`, over every path the policies name,
and fails if a combination loses a capability any member grants alone.

Scope-gated rules (`scopes = ["shared"]`) are stored unmerged and layered
additively, so `-shared` never narrows anything.

**Known limitation, unchanged by this feature.** The same precedence means a
token holding `administrator` *and* a module policy can be narrowed on the
module policy's specific paths: `administrator` restates `default`'s paths
but cannot restate templated ones. This already applied to `pki-user` and the
other engine baselines. Do not combine `administrator` with module policies.

## Seeding and upgrades

Seeded with `load_acl_policy`: written on first unseal (and on the first
unseal after upgrading), then owned by the operator, like `pki-user`. A policy
an operator already created under one of these names is left untouched. Later
releases that change a text do not overwrite an existing copy.

The older baselines (`pki-user`, `pki-admin`, `totp-*`, `transit-*`, `ldap-*`,
`standard-user`, `standard-user-readonly`, `secret-author`, `shared-access`)
are still seeded and unchanged, so existing assignments keep working.

## What Is Not Yet Implemented

- End-to-end tests driving each engine through the HTTP API with a token
  holding only one variant.
- Module policies for `rustion/`, `ssh-broker/` and other modules not listed.
- Seeding into namespace keyspaces (see above).
- `resource-connect` does not grant `update` on the resource record, so the
  "recent sessions" stamp the desktop app writes after a session is refused
  for a connect-only holder; the session itself is unaffected.
