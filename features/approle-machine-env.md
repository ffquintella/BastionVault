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

## Login flow (`path_login.rs`)

1. Validate role_id + secret_id (unchanged); capture the secret ID's `environments`.
2. If the gate is on: require `machine_token`, look it up in the token store, require it is
   FerroGate-issued (`meta.mount_path == "ferrogate/"`) and non-root, resolve
   `machine_id = ferrogate::machine_id(spiffe_id)`, require it ∈ `role.bound_machines`, and
   best-effort re-check the machine is still `approved` (cross-mount read via
   `router.matching_view("auth/ferrogate/")`). Capture the binding's `environments`.
3. Stamp the token metadata: `spiffe_id`, `machine_id`, and (when either scope is non-empty)
   `approle_env_scoped=true`, `approle_env_secret`, `approle_env_machine`.

## Enforcement (`kv_v2/mod.rs`)

`enforce_env_scope` (pure core `env_scope_allows`) runs in the KV read/write handlers: an
env-scoped token must supply an `env` that glob-matches **both** the secret-ID and machine scopes
(each empty list = unrestricted for that dimension); a scoped token with no `env` is denied. Reuses
`utils::string::globbed_strings_match` (same matcher as policy `allowed_parameters`). Non-scoped
tokens are unaffected. See [[per-env-kv-feature]] and `features/kv-environments.md`.

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

- Backend: **Done** (data model, routes, login gate, KV enforcement, config gate).
- GUI: **Done** (Machines tab, env selector, banner).
- Tests: unit tests for `env_scope_allows`, machine-binding CRUD, secret-ID env round-trip, and the
  mandatory-machine login gate; 195 GUI vitest pass.
- **Real MIA end-to-end test** (`test_approle_login_with_live_mia_machine_token` in
  `path_role.rs`): mints a genuine DPoP-bound FerroGate child token from the **locally-running MIA
  agent** (JWKS + trust domain fetched live via `ferrogate_mia::build_autoconfig`), logs it into a
  `ferrogate` mount (root-bootstrap auto-approve), binds that machine to an AppRole, and asserts the
  env-scoped AppRole login succeeds. **Self-skipping**: returns early with a printed skip line when
  no local MIA socket is reachable or CMIS is unavailable (off-VPN). Unix + async only. Run with
  `cargo test --lib test_approle_login_with_live_mia_machine_token -- --nocapture`.
