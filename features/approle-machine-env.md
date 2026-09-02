# AppRole machine binding + per-environment secret IDs

> **Naming note:** the auth method's user-facing designation is now **AppID** (GUI, docs,
> help strings) since it identifies an application/machine rather than a role. The API type
> and all `auth/approle/*` paths in this spec are unchanged for Vault compatibility.

## Summary

Makes AppRole a two-factor, environment-aware machine credential:

1. **Mandatory machine binding.** Every AppRole login must present a live FerroGate machine token
   (`machine_token`) whose machine is bound to the role. Several machines can be bound to one role.
2. **Per-environment scoping.** Secret IDs and machine bindings each carry an environment glob list
   (empty = all; wildcards like `prod-*` allowed). The issued token is restricted to the
   intersection, enforced by the KV v2 engine (force-env-and-restrict).

## Model

- `RoleEntry.bound_machines: Vec<MachineBinding>` where
  `MachineBinding { machine_id, spiffe_id, environments }`
  (`src/modules/credential/approle/path_role.rs`).
- `SecretIdStorageEntry.environments: Vec<String>`
  (`src/modules/credential/approle/validation.rs`).
- Server gate `Core::approle_require_machine: AtomicBool` (default **true**), persisted in the
  system view at `core/approle-require-machine`, loaded at unseal (`src/core.rs`). Read/set via
  `auth/approle/config { require_machine }`.

## Endpoints

| Path | Ops | Purpose |
|------|-----|---------|
| `auth/approle/config` | Read, Write | Get/set the `require_machine` gate |
| `auth/approle/role/<role>/machine` | List, Write | List bindings / add-update one (`machine_id`\|`spiffe_id` + `environments`) |
| `auth/approle/role/<role>/machine/<machine_id>` | Read, Delete | Read/remove one binding |
| `auth/approle/role/<role>/secret-id` | Write | Now also accepts `environments` |
| `auth/approle/login` | Write | Now also accepts `machine_token` (required when gated) |
| `auth/approle/role/<role>/bypass-machine-binding` | Read, Write, Delete | Per-application exemption from the gate (`DELETE` restores `false`) |
| `auth/approle/role/<role>/bound-source-ips` | Read, Write, Delete | Source-address filter for logins against this role |

## Login flow (`path_login.rs`)

1. Validate role_id + secret_id (unchanged); capture the secret ID's `environments`.
1b. If `role.bound_source_ips` is non-empty, require the connection's resolved **client** IP to
   match one entry (`bv_utils::ip_filter`). The address comes from
   `Connection::client_ip()` (`crates/bv-logical/src/connection.rs`), which prefers the
   post-`X-Forwarded-For` `peer_addr_derived` and otherwise takes the address portion of
   `peer_addr` — never the raw `peer_addr`, which carries `ip:port` and fails an IP parser
   closed. The same resolution applies to the three `secret_id_bound_cidrs`/`cidr_list` checks on
   this path. Fails closed: no connection info, no resolvable client address, an unparsable
   address or an unparsable rule refuses the login. See `CHANGELOG.md` `[Unreleased]` → Fixed →
   "AppRole source-address restrictions".
2. If `role.bypass_machine_binding` is set, skip the machine check entirely, stamp
   `approle_machine_bypass=true` and set `Auth::machine_identity_exempt` so the issued token is
   also exempt from the *separate* server-wide FerroGate `require_machine_identity` gate at the
   token layer (`TokenStore::pre_route`). No `spiffe_id`/`machine_id` is stamped — the exemption is
   a typed field on the token entry, deliberately not a metadata key, because `auth/token/create`
   copies its caller-supplied `meta` map onto the new token verbatim. Child tokens inherit it.
   Otherwise, if the gate is on: require `machine_token`, look it up in the token store, require it is
   FerroGate-issued (`meta.mount_path == "ferrogate/"`) and non-root, resolve
   `machine_id = ferrogate::machine_id(spiffe_id)`, require it ∈ `role.bound_machines`, and
   best-effort re-check the machine is still `approved` (cross-mount read via
   `router.matching_view("auth/ferrogate/")`). Capture the binding's `environments`.
3. Stamp the token metadata: `spiffe_id`, `machine_id`, and (when either scope is non-empty)
   `approle_env_scoped=true`, `approle_env_secret`, `approle_env_machine`.
4. Set `Auth::display_name` to the role name. `TokenStore::post_route` prefixes the mount, so an
   AppID session audits as `approle-<id>` — every audit surface resolves "who" through
   `bv_logical::split_principal`, which falls back to the display name for a token with no bound
   human. Left unset, every AppID in the deployment audited as the bare mount name `approle`.

## Enforcement (`kv_v2/mod.rs`)

`enforce_env_scope` (pure core `env_scope_allows`) runs in the KV read/write handlers: an
env-scoped token must supply an `env` that glob-matches **both** the secret-ID and machine scopes
(each empty list = unrestricted for that dimension); a scoped token with no `env` is denied. Reuses
`utils::string::globbed_strings_match` (same matcher as policy `allowed_parameters`). Non-scoped
tokens are unaffected. See [[per-env-kv-feature]] and `features/kv-environments.md`.

**The scope is inherited by child tokens.** Because a non-scoped token passes `enforce_env_scope`
unchanged, the *absence* of `approle_env_scoped` is what grants access — so a scoped AppID holding a
grant on `auth/token/create` used to mint itself an unscoped child that read every environment,
including the base (non-env) secrets a scoped token is barred from. `handle_create` builds the
child's `meta` from the request body, so the scope was simply dropped.
`TokenStore::handle_create` now copies every `approle_env_*` key from the parent's entry onto the
child (`INHERITED_TOKEN_META_PREFIXES` / `inherit_restriction_meta` in
`crates/bv-kernel/src/modules/auth/token_store.rs`), the same rule already applied to
`bound_cidrs` and the machine-identity exemption: a restriction a token carries must not be
escapable by one `auth/token/create`. The prefix, rather than the three key names, is what is
inherited, so a fourth `approle_env_*` key is covered on the day it is written.

Only the *restrictions* are inherited, never the identities — `spiffe_id`, `mount_path`,
`username`, `entity_id` and `role_name` stay with the parent, because inheriting an identity
widens (a child of a machine-bound token would satisfy `require_machine_identity` by descent, and
a child of a FerroGate token would be replayable as a `machine_token`). See
`RESERVED_TOKEN_META_KEYS` in `crates/bv-logical/src/auth.rs` for the complementary rule that
stops a caller *writing* these keys, and `CHANGELOG.md` `[Unreleased]` → Security → "Token
metadata is no longer a caller-writable authorization channel".

## Per-application escape hatch and source filter

Two role-level fields carry an application that cannot run a machine identity agent:

- `bypass_machine_binding: bool` (default false) — that role authenticates on the AppID
  credentials alone, and the token it receives is exempt from the token-layer
  `require_machine_identity` gate as well. Scoped to the one role; the server-wide gate is
  untouched for everything else. Both the configuration write and every bypassed login are logged
  to the `security` target, and the write is recorded in the AppID audit trail. A role whose only
  "constraint" was `bound_machines` no longer satisfies `validate_role_constraints` once bypassed.
  Clearing the flag re-gates the ID at its next login; tokens already issued keep the exemption
  until they expire.
- `bound_source_ips: Vec<String>` — a mixed list of single addresses, CIDR blocks,
  address + dotted netmask, and inclusive `start-end` ranges (`bv_utils::ip_filter`, IPv4 and
  IPv6). Validated on write. Independent of `bypass_machine_binding`, but the intended pairing:
  an ID that logs in without machine attestation should be pinned to where the app runs.

## Rollout

Because binding is mandatory by default, existing roles stop authenticating once this ships until a
machine is bound. Stage rollout with `auth/approle/config { require_machine: false }`, bind machines
to each role, then re-enable.

## GUI

`gui/src/routes/AppRolePage.tsx`: Machines tab (bind/unbind approved FerroGate machines with
per-binding environment chips + no-machine banner), secret-ID generation environment selector, and
environment display in the accessor detail. Tauri commands in
`gui/src-tauri/src/commands/approle.rs`.

## Current State

- Backend: **Done** (data model, routes, login gate, KV enforcement, config gate,
  per-role `bypass_machine_binding` incl. the token-layer exemption, `bound_source_ips` filter).
- GUI: **Done** (Machines tab, env selector, banner, bypass toggle + source IP filter field).
- Tests: unit tests for `env_scope_allows`, machine-binding CRUD, secret-ID env round-trip, the
  mandatory-machine login gate, `test_approle_bypass_machine_binding`,
  `test_bypassed_appid_survives_the_server_machine_identity_gate` (which also pins the
  `approle-<id>` audit attribution) and `test_approle_bound_source_ips`
  (`src/engine_tests/approle.rs`), `test_machine_identity_predicate`,
  `test_child_token_inherits_the_machine_identity_exemption` and
  `test_child_token_inherits_the_approle_environment_scope` (`bv-kernel` token store) plus the
  end-to-end `test_approle_env_scope_survives_token_create` (`src/engine_tests/approle.rs`), which
  logs a scoped AppID in for real, mints a child through `auth/token/create` and asserts the child
  is still refused the base (non-env) secret and an out-of-scope environment, plus the
  `ip_filter` parser and
  matcher unit tests in `bv-utils`. The client-IP resolution the source-address checks depend on is
  covered by `test_approle_secret_id_bound_cidrs_use_the_client_ip` (`src/engine_tests/approle.rs`)
  and the `client_ip` unit tests in `bv-logical`.
- **Real MIA end-to-end test** (`test_approle_login_with_live_mia_machine_token` in
  `path_role.rs`): mints a genuine DPoP-bound FerroGate child token from the **locally-running MIA
  agent** (JWKS + trust domain fetched live via `ferrogate_mia::build_autoconfig`), logs it into a
  `ferrogate` mount (root-bootstrap auto-approve), binds that machine to an AppRole, and asserts the
  env-scoped AppRole login succeeds. **Self-skipping**: returns early with a printed skip line when
  no local MIA socket is reachable or CMIS is unavailable (off-VPN). Unix + async only. Run with
  `cargo test --lib test_approle_login_with_live_mia_machine_token -- --nocapture`.
