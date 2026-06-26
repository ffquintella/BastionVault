# Feature: Default Resource Account (per-user, per-OS login name)

## Summary

Each vault user can record an optional **default resource account** — the OS
login name that operator uses on target hosts — one value per OS family
(`linux` / `macos` / `windows`). A connection profile opts in by selecting the
new **`default-account`** credential source. At connect time the login name is
the *connecting* operator's account for the target's OS, not a username pinned
on the profile.

This lets a resource be configured once ("log in as whoever is connecting,
using their own named account") instead of pinning a single shared username on
every profile. It is fully opt-in: resources whose profiles use any other
credential source are unaffected, and a user with no account configured simply
can't launch a `default-account` profile (it fails closed with a clear message).

The stored value is a login **name**, never a secret. The credential itself is
still brokered (SSH engine) or prompted at connect (RDP), so a name here cannot
by itself authenticate anywhere — the SSH role's allowed principals and the
target's own auth still gate the login.

## Motivation

- **Per-operator accountability.** Organisations that give each operator a named
  account on target hosts (`felipe-admin`, `CORP\felipe`) want the resource to
  delegate the login name to the connecting operator rather than store one
  shared username. This makes target-side logs attribute actions to the real
  person.
- **Pairs with brokered SSH.** The SSH login-brokering model already mints a
  per-connect cert from the SSH engine. `default-account` simply makes the cert
  principal the connecting operator's account — a natural fit with
  `features/ssh-resource-login-brokering.md`.
- **One profile, many operators.** A single connection profile serves a whole
  team; the username resolves per connecting user instead of needing one profile
  per person.

## Design

### Storage (`src/modules/identity/default_account.rs`)

`DefaultResourceAccountStore` mirrors the namespace-assignment store
(`src/modules/namespace/ns_assignment.rs`): a barrier-root key
`identity/default-account/<b64url(mount)>.<b64url(name)>` → `DefaultResourceAccount`
(`{ mount, name, linux, macos, windows, updated_at }`). It lives at the raw
barrier root because the connect path must read it regardless of the operator's
active namespace. All OS fields are `#[serde(default)]` and trimmed on write; an
all-empty record is deleted (back to unconfigured). No record ⇒ unconfigured.

### API (v2)

- `v2/sys/identity/default-account/{mount}/{name}` — Read / Write / Delete
  (admin). Body fields `linux` / `macos` / `windows`. Read returns the explicit
  empty (unconfigured) state rather than 404 so the GUI renders a blank
  editable form. Policy-gated (not root-scoped — see below).
- `v2/sys/identity/default-account/self` — Read. Resolves the *calling*
  principal's `(mount, name)` from the request token's metadata (`mount_path` +
  `username`, stamped at userpass login) and returns that user's accounts.
  Readable by any authenticated caller — the Connect path uses its own token, so
  a client can never read or claim another operator's account.
- `v2/sys/identity/default-account` — List (admin), for completeness.

HTTP shims are registered **v2-only** in `init_sys_service`
(`src/http/sys.rs`), siblings to `capabilities-self` / `policy-tests`. The
`self` and bare-list resources are registered before the `{path:.*}` wildcard so
they win the match. The admin paths are intentionally **not** in `root_paths`:
`root_paths` glob matching is longest-prefix, so a `default-account/*` entry
would swallow `default-account/self` and force it root-only, breaking the
connect path. Admin access is gated by policy on the explicit mount/name paths;
the GUI uses an admin/root token (`make_request_root`).

The `self` handler resolves the caller's principal in two steps: the
`(mount_path, username)` stamped at login (userpass / ferrogate fast path),
then **every alias on the caller's identity entity** (`EntityAlias` carries
`mount`+`name` directly). This covers AppRole, OIDC, SAML, and cert logins — any
entity-backed principal — not just userpass. The first principal with a record
wins. The endpoint is caller-scoped, so a token only ever resolves its own
record.

### Connect resolution (`gui/src-tauri/src/commands/connect.rs`)

The `default-account` credential source carries the same `ssh_mount` /
`ssh_role` / `mode` fields as `ssh-engine`.

- **SSH:** `resolve_default_account_ssh` reads `…/default-account/self`, picks
  the account for the resource's `os_type` (Windows→`windows`, macOS→`macos`,
  everything else→`linux`), and delegates to the SSH-engine resolver with the
  account injected as the login principal (`valid_principals` for CA mode, the
  OTP username for OTP mode). The brokered login-class gate accepts
  `default-account` alongside `ssh-engine`.
- **RDP:** the account supplies the Windows login user. The password comes from
  the operator's **optional stored Windows password** when set; otherwise it is
  prompted at connect through the existing operator-credential channel. The
  GUI decides by checking `has_windows_password` (`get_default_account_self`)
  and only opens the prompt when no password is stored. The typed username is
  ignored — the account is authoritative and resolved server-side.
- **Fails closed:** if the connecting user has no account for the target's OS,
  the connect aborts with an operator-facing message rather than silently
  substituting a profile username.

### Stored Windows password (optional)

The record holds an optional `windows_password`, encrypted at rest behind the
barrier like every other field here. It is **write-preserve**: a write that
omits the field keeps the stored value, an empty string clears it. It is
**masked** everywhere except the caller's own `self` read — admin read / list
surface only `has_windows_password`, and even the GUI `get_default_account_self`
command strips the plaintext (only the connect host, in Rust, consumes it). SSH
default accounts never use it (those logins are brokered).

### GUI

- **Edit User modal** (`gui/src/routes/UsersPage.tsx`): a *Default Resource
  Account* section with three inputs (Linux/Unix, macOS, Windows), loaded and
  saved alongside the existing namespace-assignment side-channel via
  `api.getDefaultAccount` / `api.setDefaultAccount`.
- **Profile editor** (`gui/src/routes/ResourcesPage.tsx`): a new credential
  source "Connecting user's default account". For SSH it reuses the SSH-engine
  mount/role/mode editor; for RDP it shows an explanatory note. Helpers in
  `gui/src/lib/connectionProfiles.ts` (`validateProfile`, `isLaunchableProfile`,
  `loginClassGate`, `needsOperatorPrompt`, `validateProfileForLoginClass`) treat
  the new kind consistently.

## Scope

- **In scope:** SSH (brokered via the SSH engine) and RDP (login user + stored
  or prompted password); per-OS accounts; resolution for any entity-backed
  principal (userpass, AppRole, OIDC, SAML, cert); admin editing in the Edit
  User modal; fail-closed connect resolution.
- **Out of scope (future):** a dedicated admin grid listing / editing every
  principal's default accounts (today the GUI manages userpass via the Edit User
  modal; other principals are set via the generic admin API); per-OS passwords
  beyond Windows (SSH is always brokered, so only Windows/RDP needs one).

## Current State

**Done, including both follow-ups.** Storage + store tests, v2 API + HTTP-route
roundtrip test (incl. password masking + write-preserve + clear), connect-path
resolution (SSH + RDP) with brokered-gate integration, Tauri commands, GUI Edit
User section + profile-editor source, and `connectionProfiles` unit tests all
shipped. See `CHANGELOG.md` `[Unreleased]`.

| Phase | Status |
|---|---|
| Backend store + v2 API + HTTP shims | Done |
| Connect-time resolution (SSH brokered + RDP) | Done |
| GUI (Edit User section + profile credential source) | Done |
| FU1 — `self` resolution for any entity-backed login | Done |
| FU2 — optional stored Windows RDP password (masked / write-preserve) | Done |
| Tests (Rust store + HTTP route + GUI vitest) | Done |
