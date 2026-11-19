# Feature: UserPass Account Security (lockout, enable/disable, TOTP MFA)

## Summary

Three account-level controls layered onto the userpass credential backend:

1. **Temporary account lockout** — after a configurable number of consecutive
   failed password attempts, an account is locked for a configurable duration.
2. **Admin enable/disable switch** — an operator can disable an account,
   refusing all authentication (password and FIDO2) without deleting it.
3. **TOTP multi-factor authentication** — an account can require a TOTP second
   factor at login, validated against a key in the TOTP secret engine. A global
   master switch lets an admin enable or disable MFA for the whole mount.

All state lives on the userpass mount, barrier-encrypted at rest, and every new
field is `#[serde(default)]` so pre-existing user/config blobs read back
transparently.

## Motivation

- **Brute-force resistance at the account level.** The IP-based DoS guard
  (`src/dos/`) throttles by client IP; account lockout throttles by *principal*,
  which survives IP rotation and credential stuffing spread across many source
  addresses.
- **Operational lifecycle.** Admins need to suspend an account (offboarding,
  incident response) without destroying its identity/ownership records.
- **Second factor.** Password-only auth is insufficient for privileged
  operators; TOTP is a low-friction, phone-based second factor that reuses the
  existing TOTP secret engine.

## Design

### Storage (userpass mount)

| Key | Type | Purpose |
|---|---|---|
| `user/<name>` | `UserEntry` | Gains `disabled`, `failed_login_count`, `locked_until`, `totp_mfa_enabled`, `totp_mount`, `totp_key`, and the informational contact fields `email`, `phone`. |
| `lockout_config` | `LockoutConfig` | `enabled`, `max_failed_attempts`, `lockout_duration_secs`. |
| `mfa_config` | `TotpMfaConfig` | `enabled`, `default_mount`. |

### Routes (mount-relative, under `auth/userpass/`)

| Method | Path | Purpose |
|---|---|---|
| Read/Write | `config/lockout` | Lockout policy. |
| Read/Write | `config/mfa` | Global TOTP MFA switch + default engine mount. |
| Write | `users/<name>/unlock` | Clear a lockout and reset the failed counter. |
| Write | `users/<name>` | Now also accepts `disabled`, `totp_mfa_enabled`, `totp_mount`, `totp_key`, and the informational `email`/`phone` contact fields. |
| Write | `login/<name>` | Now also accepts `totp_code`. |

Read on `users/<name>` exposes a computed `locked` boolean (current-time
comparison against `locked_until`) plus `disabled`, `failed_login_count`, and
the TOTP binding fields. `password_hash` and `credentials_json` remain redacted.

### Login flow (`path_login.rs::login_inner`)

1. Unknown user → generic `invalid username or password`.
2. `disabled` → refuse (`account is disabled`), before the FIDO2 branch.
3. FIDO2-enabled → password login blocked (unchanged).
4. **Lockout:** if `locked_until > now` refuse with a retry hint; if a lock has
   elapsed, clear it (and the counter) and continue.
5. **Password:** on mismatch, increment `failed_login_count`; once
   `>= max_failed_attempts`, stamp `locked_until = now + duration` and reset the
   counter. Persist. Return generic error.
6. **TOTP MFA:** when the global switch *and* the per-user flag are on, a valid
   `totp_code` is mandatory. A missing/wrong code is refused and feeds the same
   lockout counter as a bad password. **Fails closed** — an unmounted engine,
   missing key, or malformed policy refuses the login.
7. **Success:** reset the counter/lock if set, then issue the token as before.

Every write in steps 4, 5 and 7 re-reads the record under the user's record
lock and changes only its own fields (T544, below); bcrypt runs before the
lock is taken.

### TOTP validation (cross-mount, fail-closed)

The TOTP engine is a sibling mount. Login reads the bound key's policy through
`core.router.matching_view(<mount>)` (the established cross-mount read pattern,
mirroring AppRole's FerroGate machine lookup) and runs the RFC 6238 check
locally, reusing `modules::totp::crypto::{step_for, hotp, ct_eq}` and the
engine's `KeyPolicy`. Replay protection (the engine's `used/` index) is
intentionally **not** consulted from userpass to avoid coupling the two
backends' storage layouts; the residual replay window is one TOTP period and the
code is always combined with the password.

### Contact fields (email / phone)

`UserEntry` carries an optional `email` and `phone` so an operator can reach a
principal out-of-band (offboarding notice, incident follow-up). These are
**purely informational** and are never consumed by any code path:

- not an authentication factor,
- not used for notifications, magic links, or password/account recovery,
- not part of any TOTP/FIDO2 enrollment.

Because they are informational — never a recovery channel — they are also
**self-editable**: see `features/self-service-profile.md`, which lets a user
maintain their own email/phone (and change their own password) through
caller-scoped `v2/sys/identity/profile/self*` routes. That feature also
documents why a failed self-service password check deliberately does *not* feed
the lockout counter described above.

`write_user` only touches each field when it is present in the request, so a
partial update (e.g. a policy change) never clears them. The email is validated
with a permissive sanity check (`is_plausible_email`: single `@`, non-empty
local part, dotted domain that does not start/end with a dot) purely to catch
typos; the phone is stored as entered after trimming. Both are surfaced on
`read_user` (they are not stripped like `password_hash`/`credentials_json`) and
editable from the Users admin page's Create and Edit dialogs.

### One username, one userpass mount (T500)

A userpass login names its identity entity `("userpass/", <username>,
<login namespace>)` whatever mount it came through (the backend never sees its
own mount path: the router strips it), and namespace assignments and the
token's `mount_path` say `userpass/` too. So two userpass mounts holding one
username were one principal: they owned each other's resources and secrets and
received each other's shares. Decision of 2026-11-18: refuse the repeat, no
migration.

- **Creation** (`users/<name>`, and `users/<name>/password` on a missing user)
  asks every other userpass mount, through the kernel's
  `AuthMountRegistry::auth_mounts_of_type`, whether it holds `user/<name>`
  (names are lower-cased). If one does: `409`, before anything is written or
  an entity provisioned. The caller is told "another userpass mount", not
  which; the `security` log names it. An unreadable mount is an error, never
  "not held". An update of a user the mount holds is unchanged. There is no
  rename route; a rename is a creation and meets the same check.
- **Existing duplicates** are kept as they are. Each unseal spawns a scan
  (`username_mounts::report_duplicate_usernames`, from `start_background`)
  that logs one WARN per username held by more than one mount, with the mount
  paths, then a count; it never fails or delays the unseal. The module keeps
  the last result (`UserPassModule::take_last_duplicate_scan`) so a test can
  see the unseal ran it. The `sync_handler` build (off by default, built by no
  CI target) detaches it on a thread instead of a task.
- **Existence check:** the `409` tells a caller who may create users on one
  mount whether a username exists on another (an administrator's right).
- **Deleting** one of two duplicates keeps the entity aliases the other
  mount's user still logs in as; deleting the last holder forgets them at root
  and in every namespace (T522), as does disabling the last mount that holds
  the name.
- **Concurrent creations (T530):** the check of the other mounts and the
  write are one step. Every HA node accepts writes (a follower forwards them
  to the Raft leader), so a lock held in one process covers no other node.
  `user_lock::lock_user_record(storage, name)` takes an in-process mutex, so
  two local tasks never wait on one backend lock together (the file backend
  polls a lock file with a blocking sleep), then the storage backend's lock:
  a Raft distributed lock with a lease on hiqlite, `GET_LOCK` on MySQL (gives
  up after 1 s and fails the request), a lock file on the file backend,
  nothing on the single-node cloud file targets. The user route, the password
  route and delete hold it to the end of the handler; bcrypt runs before it is
  taken. Of two racing creations, one gets 409. The race is between two
  creations of one name, so the lock is per name (T544 below); T530 shipped
  one lock for all names, `bv-auth/userpass/user-records`, which T544 replaced
  before a release.
- **Self-service write-back (T531):** `sys/identity/profile/self/{password,
  contact}` take the user's record lock, re-read the record and apply only
  their change to it: a user deleted meanwhile is a 404 (never re-created), one
  disabled meanwhile a 403, and an administrator's password reset meanwhile
  wins (409). The default-account self write stores no userpass record.
- **The backend's own write-backs (T544):** the failed-login counter and
  lockout, the elapsed-lock clear and the success reset in the password login,
  unlock, passkey registration and removal, and the passkey sign counter of the
  passkey login and the step-up used to read `user/<name>`, run bcrypt or a
  passkey check, and write the whole record back: a delete in between
  re-created the user, an administrator's `disabled: true` or password reset in
  between was undone, and two concurrent failed logins counted once. Each now
  re-reads the record under the user's record lock
  (`UserPassBackendInner::update_user`) and applies only its own change:
  - a user deleted meanwhile is never written back: a failed login is not
    counted, a successful login is refused (`invalid username or password`),
    unlock answers `user <name> does not exist`, a passkey registration
    `User not found`, a passkey login or step-up is refused;
  - a successful password login whose record shows a disable, a lock or a new
    password meanwhile is refused, and writes nothing;
  - a passkey login or step-up on a disabled account is refused (the passkey
    login never checked `disabled` before), as is one whose key was removed
    meanwhile or whose stored counter already reached the presented one (a
    concurrent use or a clone): the counter never goes back;
  - a failed attempt arriving while a lock is in force adds nothing.
- **Why one lock per name:** the failed-login counter is written on
  unauthenticated requests, and one lock for every name would let anyone
  contend with every user write in the cluster. The lock name is
  `bv-auth/userpass/user/` plus the first 32 hex digits of the SHA-256 of a
  fixed domain string and the lower-cased name: one lock per principal across
  mounts and letter cases, never a path whatever the name holds, and 54
  characters, within MySQL's 64. A hash collision would only share a lock.
  The in-process half is 64 fixed stripes, so names sprayed at the login route
  allocate nothing. No handler holds two record locks, nor one across bcrypt
  or a passkey verification; a failed login holds it for one read and one
  write. An unknown username, or lockout disabled, takes no lock.
- Keying userpass identity by the real mount (separate entities, assignments
  and `mount_path` per mount) was decided against on 2026-11-18, see T521
  (abandoned).

### Step-up on the login mount (T532)

A userpass token's `mount_path` is `userpass/` on every mount, so connect-MFA
used to send a second mount's user to `auth/userpass/` for the step-up. It now
takes the mount from the token entry's login path (`auth/<mount>/login/...`),
as the self-service profile does, and refuses a token whose login mount is not
a userpass mount (`mfa_unavailable`). The step-up routes refuse (403) a token
that did not log in through their own mount, so no route checks another
mount's user. The ticket still binds `userpass/<name>`, the principal's
identity (T500), which is also what an MCP pairing's operator record carries.

## Defaults / operational notes

- **Lockout is enabled by default** (5 attempts / 900 s). Operators can widen,
  tighten, or disable it. Note the standard account-lockout tradeoff: a
  known-username attacker can force short self-inflicted DoS windows; tune
  `lockout_duration_secs` accordingly or disable and rely on the IP DoS guard.
- **TOTP MFA is opt-in** (`config/mfa.enabled = false` by default) so upgrades
  do not suddenly demand a second factor. Turning it off is the administrative
  "disable MFA" control and makes per-user flags inert.

## Current State

**Done** — backend (fields, config paths, unlock, login enforcement, TOTP MFA
validation), unit tests (`test_disable_and_lockout`, `test_totp_mfa_login`),
CLI `totp_code` passthrough, GUI (Account Security panel, per-user Disable /
TOTP-MFA controls, Unlock action, list status badges), Tauri commands, and
`api.ts` wrappers with tests.

| Phase | Status |
|---|---|
| Backend: enable/disable + lockout + unlock | Done |
| Backend: TOTP MFA (global switch + per-user, fail-closed) | Done |
| Backend: informational `email`/`phone` contact fields | Done |
| GUI: user controls + Account Security panel | Done |
| CLI: `totp_code` on login | Done |
| Tests (Rust unit + GUI api) | Done |
| Backend: one username per userpass mount, duplicate report at unseal (T500) | Done |
| Backend: a deleted user or disabled mount forgets its aliases in every namespace (T522) | Done |
| Backend: user creation serialised across mounts and HA nodes (T530) | Done |
| Backend: self-service writes re-read the user under that lock (T531) | Done |
| Backend: connect-MFA step-up on the token's login mount (T532) | Done |
| Backend: counters, unlock and passkey write-backs re-read the user under a per-name lock (T544) | Done |

T500 is proven by `src/engine_tests/userpass_mounts.rs` (refusal in any case,
by both creating routes, no record or entity on refusal, same-mount updates,
the delete rule, the unseal scan on planted duplicates with a seal and unseal).

T522: deleting a user, or disabling its mount, forgets its alias at root and in
every namespace keyspace found in storage, under T500's keeping rule; the old
entities keep their owner and share records for the transfer endpoints, and
their plugin data goes once no alias anywhere names them (for good; this now
includes namespace entities a delete used to leave). If the other mounts
cannot be read, the aliases are kept, never forgotten on a guess. A partial
failure is a `data.warnings` list in the response; deleting the name again
retries. Proven by
`src/engine_tests/principal_aliases.rs` (namespace logins before the delete and
after the re-creation, AppRole, the keeping rule, disable, the purge).

T530 is proven by `userpass_mounts.rs`
(`simultaneous_creations_of_one_name_on_two_mounts_admit_one`: two OS threads,
user and password routes; both passed before), T531 by
`self_profile_writes.rs` (delete, disable and admin reset while the write
waits), T532 by `connect_mfa_mounts.rs` (a second mount's user, the root
mount unchanged, a pre-T500 duplicate without factors on the root mount), and
T533, the same refusal for AppRole role names, by `approle_mounts.rs`.

T544 is proven by `src/engine_tests/userpass_record_writes.rs`: a delete, a
disable and a password reset while a failed or successful password login, an
unlock, a passkey removal, a passkey registration, a passkey login (also a
counter moved past the assertion) and a passkey step-up wait for the record
lock, driven by a software Ed25519 authenticator; all but the per-name check
failed before. That check holds dave's lock while carol fails a login; the
lock-name rules are unit tests in `user_lock.rs`.

### Not yet implemented

- Separate identity entities per userpass mount: decided against on
  2026-11-18, see T521 (abandoned). A username may exist in only one userpass
  mount, and pre-T500 duplicates stay one entity.
- A successful login with no counter to reset writes nothing and takes no
  lock, so one that read the record just before a delete or a disable still
  gets its token (as any check-then-act read does). T544 closes the
  write-backs, not that window.
- On MySQL a write that waits more than a second for another node's record
  lock fails; for a failed login that means the attempt is refused with a
  storage error and not counted.
- Aliases a delete left in a namespace before T522 are not migrated: a name
  re-created since logs in there as the old entity. Deleting a name no mount
  holds clears them; no endpoint lists entities no alias names, or the
  objects an entity owns (T526).
- Group membership and namespace assignments name a user by username, so a
  user re-created under a deleted name is back in them.
- GUI operator-login MFA prompt (the desktop app's own sign-in does not yet
  prompt for a TOTP code; the backend endpoint and CLI accept it today).
- Namespace-aware TOTP mount resolution follows the existing cross-mount
  convention (root-namespace mount path); non-root-namespace TOTP engines are
  not yet resolved for MFA.
