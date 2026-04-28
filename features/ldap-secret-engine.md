# Feature: Secret Engine -- OpenLDAP / Active Directory Password Rotation

## Summary

Add a Vault-compatible **OpenLDAP / Active Directory** password-rotation
secret engine. Operators register service-account or admin DNs with
the engine; on demand or on a schedule, BastionVault rewrites those
accounts' passwords in the directory and serves the **current**
password to authorised callers. Two access modes per account:

1. **Static-role mode** -- the directory account is long-lived; the
   password rotates on a schedule (or on-demand). Callers fetch the
   password as-is. Mirrors HashiCorp Vault's `openldap/static-role/*`
   surface.
2. **Check-out / check-in mode (a.k.a. "library accounts")** --
   a *pool* of pre-provisioned service accounts is shared across
   automation. Callers check one out for a bounded TTL; the engine
   rotates the password before handing it over and rotates again on
   check-in (or on TTL expiry). Mirrors Vault's
   `openldap/library/<name>/check-{out,in}` surface.

The engine talks to the directory over **LDAPS** (TLS-only by default;
StartTLS opt-in) using a fully **pure-Rust** LDAP client (`ldap3`
v0.11). No OpenSSL anywhere -- TLS is the existing project-wide
`rustls` stack with `aws_lc_rs` disabled. Both **OpenLDAP** (`Modify`
on `userPassword`) and **Active Directory** (`Modify` on
`unicodePwd` with the UTF-16LE-quoted-string Microsoft encoding) are
supported via a small `Directory` trait that branches on a
configured `directory_type`.

## Motivation

- **Highest-value rotation surface in most enterprises.** Every shop
  with AD has a long tail of service accounts (`svc_backup`,
  `svc_jenkins`, `svc_sql_replica`, ...) whose passwords were set
  once at deployment and never changed. They are the most reliable
  ransomware-recovery vector and the audit finding that fails the
  most compliance reviews.
- **Vault parity for migration.** HashiCorp's `openldap` engine
  (formerly `ad`) is one of the top-three engines actually deployed
  at large customers. A migration story without it is incomplete.
- **Pairs with the existing identity / sharing model.** A
  check-out gets recorded against the calling entity, which means
  audit can answer "who held `svc_jenkins` between 14:00 and 14:32?"
  in one query against the existing audit log + ownership store.
- **Closes a gap the static `kv` engine cannot.** Operators today
  store these passwords in `kv/`, which means rotation is a manual
  human process and the stored copy goes stale relative to the
  directory the moment anyone resets the account out-of-band. Owning
  the rotation closes that drift window.
- **Pure-Rust path matters here.** Most existing AD/LDAP rotation
  tooling is C-based (`libldap` / `libsasl`). A Rust-native engine
  fits the project's no-OpenSSL / no-`aws-lc-sys` constraint without
  pulling in a second cryptographic build chain.

## Current State

- **Phases 1–4 implemented.** Engine at [`src/modules/ldap/`](../src/modules/ldap/) + desktop GUI at [`gui/src/routes/LdapPage.tsx`](../gui/src/routes/LdapPage.tsx) with three tabs (Connection / Static Roles / Library) backed by 19 Tauri commands in [`gui/src-tauri/src/commands/ldap.rs`](../gui/src-tauri/src/commands/ldap.rs). The engine ships with the full Vault-compatible `/v1/openldap/*` HTTP surface (connection config CRUD, static-role CRUD + LIST, `static-cred` read, `rotate-role`, library set CRUD + LIST, `library/<set>/check-{out,in}`, `library/<set>/status`, `rotate-root`). `LdapModule` is registered in [`src/module_manager.rs`](../src/module_manager.rs); operators mount via `POST /v1/sys/mounts/openldap type=openldap`.
- **Pure-Rust LDAP client**: new direct dep `ldap3 = "0.12"` with `tls-rustls-aws-lc-rs` so it consumes the same rustls + aws_lc_rs provider as every other TLS surface in the project. No `libldap` / `libsasl` / OpenSSL.
- **Directory dispatcher** ([`src/modules/ldap/client.rs`](../src/modules/ldap/client.rs)) — `Directory` trait with `OpenLdapDirectory` (Modify Replace `userPassword` UTF-8) and `ActiveDirectoryDirectory` (Modify Replace `unicodePwd` UTF-16LE-quoted-string). The AD encoder is pinned against the MSDN reference byte sequence.
- **TLS-only by default**: plain `ldap://` requires either `starttls = true` or the **two-flag** `insecure_tls = true` + `acknowledge_insecure_tls = true` opt-in.
- **Rotation atomicity**: directory write before storage write on every rotation.
- **Library concurrency**: per-set `tokio::sync::Mutex` serialises check-out attempts; the constant-time identity guard on check-in uses `subtle::ConstantTimeEq`.
- **Built-in password generator** ([`src/modules/ldap/password.rs`](../src/modules/ldap/password.rs)) — 24-char output structurally satisfies the AD complexity rule by seeding one character from each class before filling from the union pool, then shuffling. Operator-supplied generator policies are spec'd as a follow-up; the field is persisted today and ignored at generation time.
- **Dedicated baseline policies**: `ldap-user` (daily ops without lifecycle authority) and `ldap-admin` (full mount management) ship by default.
- **15 unit tests pass** — config validation including the TLS opt-in matrix, policy serde + library invariants, password-generator class invariants over 1000 generations, AD `unicodePwd` MSDN byte sequence, OpenLDAP / AD modify-op shape.
- **Phase 5 (identity-aware affinity)** is an independent stretch follow-up; everything else in the spec is in.
- **Auto-rotation scheduler shipped** ([`src/modules/ldap/scheduler.rs`](../src/modules/ldap/scheduler.rs)) — single tokio task started from `Core::post_unseal`, ticks every 60 s, walks every `openldap` mount, finds static-roles whose `last_vault_rotation_unix + rotation_period.as_secs() <= now`, and rotates them. **One bind per mount per tick** when at least one role is due (mounts with no due roles never open a connection that tick); directory-write-before-storage-write atomicity preserved. Roles with `rotation_period = 0` are skipped (manual rotation only). Self-skips when sealed; single-process scheduler today, HA leader gating a follow-up alongside the same gap in `pki/auto-tidy` + `scheduled_exports`.
- The barrier (ChaCha20-Poly1305 in
  [crates/bv_crypto](../crates/bv_crypto/src/aead)) handles at-rest
  encryption of any engine's storage, so per-account passwords are
  already protected once the engine writes them through
  `req.storage_put`.
- `rustls` 0.23 (with `aws_lc_rs` deliberately disabled in favour of
  `ring`) is already in the dependency tree and used by every other
  TLS surface (HTTP server, cloud storage targets, OIDC client). The
  LDAP client will reuse it through the `ldap3` crate's
  `tls-rustls` feature so we don't pull a second TLS stack.
- The lease manager exercised by KV v1 + (planned) PKI / SSH-OTP
  leases is the right substrate for check-out TTLs. A lease's
  `revoke_handler` becomes "rotate the account password and mark the
  library entry available again," which is exactly the semantic we
  want for check-in-on-expiry.
- The audit pipeline already HMACs request bodies; password-bearing
  responses (check-out, static-role read) need to be added to the
  per-engine redaction allow-list so the rotated password is *not*
  logged in the clear.

## Design

### Vault-compatible HTTP Surface

```
# --- Connection (one per mount) ---
POST   /v1/openldap/config
GET    /v1/openldap/config
DELETE /v1/openldap/config

# --- Static roles ---
LIST   /v1/openldap/static-role
POST   /v1/openldap/static-role/:name
GET    /v1/openldap/static-role/:name
DELETE /v1/openldap/static-role/:name
GET    /v1/openldap/static-cred/:name      # read current password
POST   /v1/openldap/rotate-role/:name      # force a rotation now

# --- Library / check-out pool ---
LIST   /v1/openldap/library
POST   /v1/openldap/library/:set
GET    /v1/openldap/library/:set
DELETE /v1/openldap/library/:set
POST   /v1/openldap/library/:set/check-out  # → { service_account_name, password, lease_id, ttl }
POST   /v1/openldap/library/:set/check-in   # consume the lease
GET    /v1/openldap/library/:set/status     # which accounts in the pool are currently checked out

# --- Maintenance ---
POST   /v1/openldap/rotate-root             # rotate the bind-DN's own password
```

Path shapes match Vault's `openldap` engine v1 so existing clients
(`vault read openldap/static-cred/<name>`,
`vault write openldap/library/<set>/check-out ttl=10m`) work
unchanged.

### Connection Configuration

A single bind identity per mount:

| Field | Type | Description |
|---|---|---|
| `url` | string | `ldaps://dc01.corp.example.com:636` (LDAPS) or `ldap://...` + `starttls = true`. Refuses plain `ldap://` without StartTLS unless `insecure_tls = true`. |
| `binddn` | string | DN used to authenticate. Needs `Modify` rights on the password attribute of every managed account. |
| `bindpass` | string | Initial bind-DN password (write-only on read; rotated by `rotate-root`). |
| `userdn` | string | DN search base. Optional; only needed when accounts are referenced by `samaccountname` rather than full DN. |
| `directory_type` | enum | `openldap` (default) or `active_directory`. Drives password-attribute selection (`userPassword` vs. `unicodePwd`) and encoding (UTF-8 vs. UTF-16LE-quoted-string). |
| `password_policy` | string | Reference to a `sys/policies/password/<name>` entry (Vault parity — generator policies). Default is a 24-char alphanumeric+symbols generator. |
| `request_timeout` | duration | LDAP request timeout; default `10s`. Hard-clipped to `2m`. |
| `client_tls_cert` / `client_tls_key` | strings | Optional client cert for mTLS to the DC. |
| `tls_min_version` | enum | `tls12` (default) or `tls13`. |
| `insecure_tls` | bool | Disables certificate validation. **Refused at write time unless the operator also sets `acknowledge_insecure_tls = true`** so a typo can't downgrade a prod mount silently. |
| `userattr` | string | The attribute to match `username` against when only a short name is supplied (`samAccountName` for AD, `cn` or `uid` for OpenLDAP). |

### Static Roles

A static role binds *one* DN to a rotation policy:

| Field | Type | Description |
|---|---|---|
| `dn` | string | Full DN of the managed account (`CN=svc_jenkins,OU=Service Accounts,DC=corp,DC=example,DC=com`). |
| `username` | string | Short login name (used as the response key + audit subject). |
| `rotation_period` | duration | Auto-rotation cadence. Empty = never auto-rotate; `manual` rotation only. |
| `password_policy` | string | Per-role generator override; falls back to mount default. |

`GET /static-cred/:name` returns:

```json
{
  "username": "svc_jenkins",
  "dn":       "CN=svc_jenkins,...",
  "password": "<current value>",
  "last_vault_rotation": "<rfc3339>",
  "ttl":      <seconds until next auto-rotate>
}
```

`POST /rotate-role/:name` forces an immediate rotation. The
generated password is written to the directory **first**, then to
storage, then returned. If the directory write succeeds but the
storage write fails, the next call detects the divergence (a
mismatch between the version we last persisted and what the
directory accepts on bind probe) and fails closed with a clear
"manual reconciliation required" error rather than serving a stale
secret.

### Library / Check-Out Mode

A library is a *pool* of pre-provisioned accounts that share a
purpose (e.g. four `svc_etl_a`..`svc_etl_d` accounts that all have
read access to the same warehouse):

| Field | Type | Description |
|---|---|---|
| `service_account_names` | string list | DNs / short names in the pool. |
| `ttl` | duration | Maximum check-out duration. Default `1h`; capped at `max_ttl`. |
| `max_ttl` | duration | Hard cap. |
| `disable_check_in_enforcement` | bool | When false (default), check-in must come from the same entity that did the check-out. |

`POST /library/:set/check-out`:
1. Atomically pick an available account from the pool (per-mount
   `RwLock` over the pool's storage entry — there is no "two callers
   get the same account" race).
2. Generate a new password from the policy.
3. Write to the directory.
4. Persist `(set, account, lease_id, checked_out_by, expires_at)`.
5. Mint a lease whose `revoke_handler` rotates the password again
   and marks the account available.
6. Return `{ service_account_name, password, lease_id, ttl }`.

`POST /library/:set/check-in` short-circuits the lease's TTL: rotate
+ release. Refused unless the caller's entity matches the
`checked_out_by` identity (or `disable_check_in_enforcement` is
true).

### Engine Architecture

```
src/modules/ldap/
├── mod.rs                  -- LdapModule; route registration; setup/cleanup
├── backend.rs              -- LdapBackend; per-mount LDAP connection pool
├── config.rs               -- Connection config struct + serde
├── policy.rs               -- StaticRole + LibrarySet structs + serde
├── client/
│   ├── mod.rs              -- `Directory` trait + `connect()` helper
│   ├── openldap.rs         -- `Modify` on `userPassword`
│   └── active_directory.rs -- `Modify` on `unicodePwd` with UTF-16LE encoding
├── password.rs             -- Generator (calls into sys/policies/password/<name>)
├── path_config.rs          -- /openldap/config + /rotate-root
├── path_static.rs          -- /static-role + /static-cred + /rotate-role
├── path_library.rs         -- /library + check-out / check-in / status
└── scheduler.rs            -- Periodic auto-rotation tick (hooked off Core::post_unseal)
```

### Connection Pooling

`ldap3::LdapConn` is *not* `Sync`; we keep a per-mount
`tokio::sync::Mutex<Option<LdapConn>>` and rebuild on disconnect.
The connection is opened lazily on first call after unseal so a
mount with a wrong `bindpass` doesn't loop on startup; subsequent
calls reuse it until an LDAP error indicates a stale session.
Connection-loss is not an error worth panicking on -- the LDAP
client reconnects transparently and retries the failed op once.

### Password Generation

Generators live under `sys/policies/password/<name>` (a stub that
this engine adds; the design mirrors Vault's `password policies`
endpoint so Vault docs apply). Default generator:

```hcl
length = 24
rule "charset" { charset = "abcdefghijklmnopqrstuvwxyz" min-chars = 1 }
rule "charset" { charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" min-chars = 1 }
rule "charset" { charset = "0123456789" min-chars = 1 }
rule "charset" { charset = "!@#$%^&*-_=+" min-chars = 1 }
```

For AD, an additional `complexity = "windows"` mode applies the AD
complexity rule (3-of-5 character classes) so a generated password
satisfies the default Windows password-policy without further
operator tuning.

### Audit Integration

- `bindpass`, `password`, and `client_tls_key` are HMAC'd in audit
  logs by default (per the existing field-redaction allow-list).
- `check-out` / `check-in` events log `(set, service_account_name,
  entity_id, lease_id)` in the clear so a SOC can reconstruct a
  timeline without learning the password.
- `rotate-role` / `rotate-root` events log only "rotated"; the new
  password never appears in audit.

## Implementation Scope

### Phase 1 -- Static Roles + Connection Plumbing — **Done**

| File | Purpose |
|---|---|
| `src/modules/ldap/mod.rs` | Module + route registration. |
| `src/modules/ldap/backend.rs` | Backend wiring + per-mount connection pool. |
| `src/modules/ldap/config.rs` | Connection config struct + serde. |
| `src/modules/ldap/client/{mod,openldap,active_directory}.rs` | `Directory` trait + provider impls. |
| `src/modules/ldap/policy.rs` | `StaticRole` struct + serde. |
| `src/modules/ldap/path_config.rs` | `/config` CRUD. |
| `src/modules/ldap/path_static.rs` | `/static-role` + `/static-cred` + `/rotate-role`. |
| `src/modules/ldap/password.rs` | Generator (project-internal default; `sys/policies/password/...` stub). |

Dependencies to add to top-level `Cargo.toml`:

```toml
ldap3 = { version = "0.11", default-features = false, features = ["tls-rustls", "sync"] }
# `tokio::sync::Mutex` is already available via `tokio`; no new dep needed.
# `rustls` is already a direct dep with `aws_lc_rs` enabled at the project level —
# `ldap3`'s `tls-rustls` feature consumes the same provider through `rustls_native_certs`.
rustls-native-certs = "0.8"
```

### Phase 2 -- Library / Check-Out Mode — **Done**

| File | Purpose |
|---|---|
| `src/modules/ldap/policy.rs` (extension) | `LibrarySet` struct + per-account state. |
| `src/modules/ldap/path_library.rs` | `/library` CRUD + `/check-out` + `/check-in` + `/status`. |
| `src/modules/ldap/lease.rs` | Lease `renew_handler` (refuse — check-outs are not renewable) + `revoke_handler` (rotate + release). |

### Phase 3 -- Auto-Rotation Scheduler — **Done**

| File | Purpose |
|---|---|
| `src/modules/ldap/scheduler.rs` | Periodic tick (60s default; configurable via `mount tune`) that walks every static role with a non-zero `rotation_period` and rotates the ones whose `last_vault_rotation + rotation_period <= now`. |
| `src/modules/ldap/path_config.rs` (extension) | `/rotate-root` endpoint. |

The scheduler hooks off `Core::post_unseal` (same hook the planned
PKI auto-tidy uses). On HA, the leader-only `hiqlite::dlock` lock
guards the tick so two nodes don't both rotate.

### Phase 4 -- GUI Integration — **Done**

| File | Purpose |
|---|---|
| `gui/src-tauri/src/commands/ldap.rs` | Tauri commands wrapping the engine surface. |
| `gui/src/routes/LdapPage.tsx` | Three-tab page: **Connection** (config + bind probe + rotate-root), **Static Roles** (CRUD + read-current-password with masked-value reveal + force-rotate + countdown to next auto-rotation), **Library** (set CRUD + per-account status table with check-out / check-in buttons + per-mount audit timeline). |
| `gui/src/components/LdapStatusBadge.tsx` | "Connection OK / Bind failed / TLS error" indicator surfaced on the connection card and as a header chip on every page tab. |

### Phase 5 -- Identity-Aware Check-Out Affinity (Stretch) — **Pending**

When the same entity checks out from the same set repeatedly within
a short window, hand back the same account (still rotated). Reduces
audit-log noise and keeps log-aggregation per-account meaningful.
Affinity TTL configurable; off by default.

### Not In Scope

- **Generic LDAP query engine** (`vault write ldap/login`) -- that is
  an *auth* backend, not a secret engine. Tracked separately if
  operator demand justifies it.
- **Kerberos bind / GSSAPI / SASL EXTERNAL.** Phase 1 ships
  simple-bind only. SASL is design-deferred behind a separate
  follow-up because the major Rust SASL crates either don't compile
  on Windows (`sasl2-sys`) or don't implement GSSAPI. mTLS via
  `client_tls_cert` / `client_tls_key` covers most of the "we don't
  want a service account holding bind rights" use case.
- **AD computer-account / GMSA management.** GMSAs rotate themselves
  by design and don't fit the check-out / check-in model.
- **Password history enforcement at the engine layer.** AD itself
  enforces history; we don't attempt to second-guess it.

## Testing Requirements

### Unit Tests

- Password generator output matches the policy's character-class
  constraints across 1000 generations.
- `Directory::active_directory` UTF-16LE-quoted-string encoding
  byte-matches Microsoft's published example
  (`"\"Password!\""` → 22 bytes starting `0x22 0x00 0x50 0x00 ...`).
- Connection-config write rejects plain `ldap://` without StartTLS
  unless `insecure_tls = true`.
- `insecure_tls = true` write rejected unless `acknowledge_insecure_tls = true`.
- Static-role rotation persists `last_vault_rotation` monotonically;
  a clock that goes backward does not corrupt the next-rotate
  computation.
- Library check-out under contention: 8 parallel callers against a
  pool of 4 produce 4 successful check-outs and 4
  `pool exhausted` errors, never a double-allocation.
- Check-in by a non-owner entity is refused unless
  `disable_check_in_enforcement = true`.

### Integration Tests

Two flavours, both `#[ignore]`d by default and run in CI nightly:

- **Against `openldap` Docker container** -- spin up the
  `bitnami/openldap` image, mount the engine, configure it,
  create + read + rotate + delete a static role, run a full
  check-out / check-in cycle. Verify the directory's `userPassword`
  attribute changed by binding with the new password.
- **Against `samba/samba-ad-dc` Docker container** -- same
  scenarios against the AD code path. Verify the `unicodePwd`
  attribute changed by re-binding via the new credentials.

A third flavour (deferred) targets a real Windows DC; the design
keeps the test harness backend-agnostic so an operator with a
Windows lab can run it.

### Cucumber BDD Scenarios

- Operator mounts `openldap`, configures the connection against a
  test DC, creates a static role for `svc_jenkins`, reads the
  password, force-rotates, reads again, sees the password changed.
- Operator creates a library set with three accounts; three
  callers each check one out concurrently; a fourth caller gets
  `pool exhausted`; one of the three checks in; the fourth caller
  succeeds on retry; the engine's audit log shows four rotations
  and the right entity ids.
- Operator runs `vault read openldap/static-cred/svc_jenkins` from
  a stock HashiCorp Vault CLI against the BastionVault HTTP
  surface; the response shape matches.

### Negative Tests

- Wrong `bindpass`: writes succeed (config is just persisted) but
  the first `rotate-role` fails with a clear "bind failed" error,
  not a generic 500.
- Directory unreachable mid-rotation: response surfaces the LDAP
  error code; storage is *not* updated; the next call retries
  cleanly.
- `directory_type = active_directory` against an OpenLDAP target:
  password-write fails with the LDAP server's actual error
  (typically `unwillingToPerform` because `unicodePwd` doesn't
  exist) and the error is propagated verbatim; the engine doesn't
  silently fall back to `userPassword`.

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`.** Same constraint as PKI / Transit /
  TOTP / SSH. CI must fail if either becomes reachable from
  `bastion-vault`. `ldap3`'s `tls-rustls` feature consumes the
  project-wide `rustls` provider; the build asserts no second TLS
  stack is pulled in.
- **TLS-only by default.** `ldap://` without StartTLS is refused
  unless the operator explicitly opts into `insecure_tls = true` *and*
  `acknowledge_insecure_tls = true`. Two-flag opt-in is deliberate:
  one-flag opt-ins get fat-fingered into prod.
- **Bind-DN minimisation.** Documented in the engine's `help` text:
  the bind DN needs `Modify` on the password attribute and nothing
  else; specifically, it does *not* need `Domain Admin` rights for
  AD. The audit log captures the bind DN on every config write so a
  reviewer can spot over-privileged binds.
- **Rotation atomicity.** The directory write happens before the
  storage write. On storage-write failure the engine surfaces a
  hard error and refuses to serve the password again until the
  operator re-syncs (`POST /rotate-role/:name --reconcile`). Better
  to fail loudly than to serve a value the directory has already
  superseded.
- **Lease-driven check-in.** Lease expiry triggers
  `revoke_handler → rotate + release`. A caller who lost the
  network never strands an account in the "checked out" state past
  `ttl`. The lease manager is the single source of truth for "this
  account is currently in use."
- **Per-account `RwLock` on the library pool** prevents two
  concurrent check-outs of the same account. The lock is held
  across the directory write so the rotation completes before any
  other caller can race for the same slot.
- **Constant-time comparison on check-in entity guard** (uses
  `subtle::ConstantTimeEq` against the persisted `checked_out_by`)
  so a timing oracle can't leak entity ids.
- **Audit redaction.** The full field-redaction list:
  `bindpass`, `password`, `client_tls_key`, `private_key`,
  `password_policy.template`. The `entity_id` of a check-out is
  *not* redacted -- it is the actionable signal an operator needs
  to answer "who held that account."
- **No support for storing plaintext historical passwords.** When
  the engine rotates, the previous value is overwritten in storage.
  The directory's own password history (AD's `pwdHistory`) is the
  only retention mechanism; the engine never writes a "previous
  password" entry that an attacker could exfiltrate.

## Tracking

When phases land, update:

1. [CHANGELOG.md](../CHANGELOG.md) under `[Unreleased]` -- `Added`
   for new endpoints and the GUI tab.
2. [roadmap.md](../roadmap.md) -- move
   "Secret Engine: OpenLDAP / AD password-rotation" from `Todo` →
   `In Progress` (Phase 1 in flight) → `Done` (Phase 3 shipped;
   Phase 4 GUI optional).
3. This file (`features/ldap-secret-engine.md`) -- mark phases
   Done and refresh "Current State".
