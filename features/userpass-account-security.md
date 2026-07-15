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
| `user/<name>` | `UserEntry` | Gains `disabled`, `failed_login_count`, `locked_until`, `totp_mfa_enabled`, `totp_mount`, `totp_key`. |
| `lockout_config` | `LockoutConfig` | `enabled`, `max_failed_attempts`, `lockout_duration_secs`. |
| `mfa_config` | `TotpMfaConfig` | `enabled`, `default_mount`. |

### Routes (mount-relative, under `auth/userpass/`)

| Method | Path | Purpose |
|---|---|---|
| Read/Write | `config/lockout` | Lockout policy. |
| Read/Write | `config/mfa` | Global TOTP MFA switch + default engine mount. |
| Write | `users/<name>/unlock` | Clear a lockout and reset the failed counter. |
| Write | `users/<name>` | Now also accepts `disabled`, `totp_mfa_enabled`, `totp_mount`, `totp_key`. |
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

### TOTP validation (cross-mount, fail-closed)

The TOTP engine is a sibling mount. Login reads the bound key's policy through
`core.router.matching_view(<mount>)` (the established cross-mount read pattern,
mirroring AppRole's FerroGate machine lookup) and runs the RFC 6238 check
locally, reusing `modules::totp::crypto::{step_for, hotp, ct_eq}` and the
engine's `KeyPolicy`. Replay protection (the engine's `used/` index) is
intentionally **not** consulted from userpass to avoid coupling the two
backends' storage layouts; the residual replay window is one TOTP period and the
code is always combined with the password.

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
| GUI: user controls + Account Security panel | Done |
| CLI: `totp_code` on login | Done |
| Tests (Rust unit + GUI api) | Done |

### Not yet implemented

- GUI operator-login MFA prompt (the desktop app's own sign-in does not yet
  prompt for a TOTP code; the backend endpoint and CLI accept it today).
- Namespace-aware TOTP mount resolution follows the existing cross-mount
  convention (root-namespace mount path); non-root-namespace TOTP engines are
  not yet resolved for MFA.
