# Feature: Per-Environment KV v2 Secret Values

## Current State

**Status: Done.** A single KV v2 secret can hold a shared **base** key/value set
plus per-**environment** override sets; a read selects an environment and
receives the merge. The `env` request parameter is wired end-to-end so a
policy's `required_parameters = ["env"]` / `allowed_parameters = { env = [...] }`
is finally enforceable on KV reads.

What landed:

- **Request plumbing** — `src/logical/util.rs` (`split_path_query`,
  `parse_query_allowlist`) lifts allowlisted query params (`env`, `version`)
  into `req.data` at both entry boundaries: the HTTP handler
  (`src/http/logical.rs`, from `HttpRequest::query_string()`) and the embedded
  GUI backend (`gui/src-tauri/src/backend.rs`, splitting `?env=` off the path).
  This happens *before* `core.handle_request`, because the ACL check runs in the
  pre-route phase and reads `req.data`/`req.body` directly. The logical router
  (`src/logical/backend.rs`) now **merges** path captures into seeded `req.data`
  instead of replacing it.
- **Storage** — `VersionData.envs: Map<String, Value>` (`src/modules/kv_v2/version.rs`),
  serde-defaulted + `skip_serializing_if` so legacy on-disk versions are
  unchanged. `merge_env(base, overrides)` does a shallow override-wins merge.
- **Read** (`handle_data_read`) — resolves `env` from `req.data` then `req.body`;
  returns base when no env / no envs, the merge when the env is declared, and
  `Ok(None)` (HTTP 404) when an env is requested but not declared on a secret
  that has envs. Response metadata adds `resolved_env` + `available_envs`.
- **Write** (`handle_data_write`) — three modes: full multi-env (`envs` in body),
  targeted single-env patch (`env` + `data`, carries base + other envs forward),
  and legacy base-only (preserves existing envs). `env` + `envs` together is
  rejected. CAS and version pruning unchanged.
- **Engine registry** — `EngineConfig.environments: Vec<String>`
  (`src/modules/kv_v2/metadata.rs`); advisory list surfaced by the GUI dropdown.
  Free-form env names still accepted; names are sanitized (non-empty, no `/`, no
  control chars).
- **CLI** — `bvault read --env <ENV>` (appends `?env=`) and
  `bvault write --env <ENV> k=v` (targeted patch) in `src/cli/command/{read,write}.rs`.
- **GUI** — `gui/src/routes/SecretsPage.tsx`: env selector on the detail view,
  per-key inherited/override markers, env-scoped editing (saves via
  `write_secret_env`), optional environment on the create modal, and the env
  registry on the engine-config editor. `read_secret` returns env metadata.
- **Audit** — `src/audit/entry.rs` folds the non-secret `env` selector from
  `req.data` into the audited request `data` (verbatim, not HMAC'd).
- **Policy builder** — `gui/src/components/PolicyBlockEditor.tsx` has a "Restrict
  to environments" field per rule. It emits `required_parameters = ["env"]` +
  `allowed_parameters = { env = [...], "*" = [] }` via the pure
  `withEnvRestriction` / `envRestrictionOf` helpers in `gui/src/lib/policyHcl.ts`
  (the `"*" = []` sentinel keeps non-`env` parameters working so the restriction
  gates only `env`). Round-trips through the HCL source tab.
- **Tests** — `tests/test_default_logical.rs::test_kv_v2_environments` (full
  multi-env / targeted patch / legacy carry-forward / strict miss / registry),
  `merge_env` + serde backward-compat units in `version.rs`, the env ACL unit in
  `policy.rs` (`test_env_required_and_allowed_parameter`), `split_path_query`
  units in `util.rs`, `gui/src/test/secretsEnv.test.ts` for the API wiring, and
  the `withEnvRestriction` round-trip units in `gui/src/test/policyHcl.test.ts`.

## Summary

Model environment-specific configuration (prod/staging/dev) as one logical
secret rather than many sibling paths. Reading with `?env=prod` returns the
shared base merged with the prod overrides, so callers fetch "the value for my
environment" from a single, policy-gated path.

## Motivation

Teams keep the same logical secret (a DB connection, an API base URL, a feature
flag bag) across several environments where only a few keys differ per
environment. Encoding the environment in the path (`secret/app/prod/db` vs
`secret/app/staging/db`) duplicates the shared keys and fragments ACLs. A field
policy already used `required_parameters = ["env"]` expecting reads to be scoped
by environment — but nothing carried `env` into the request, so the rule
silently denied every read.

## Request contract

- **Read**: `GET /v1/<mount>/data/<path>?env=<name>` — `env` (and `version`) are
  lifted from the query into `req.data`. Response:
  `{ data: <merged>, metadata: { resolved_env, available_envs, version, ... } }`.
- **Targeted write**: `POST` body `{ "env": "prod", "data": { ...overrides } }`.
- **Full multi-env write**: `POST` body `{ "data": { ...base }, "envs": { "prod": {...}, "staging": {...} } }`.
- **Legacy write**: `POST` body `{ "data": { ...base } }` (existing envs preserved).
- **Registry**: `POST /v1/<mount>/config` body `{ "environments": ["prod", ...] }`.

## Policy interplay

```hcl
path "secret/data/apps/netrisk/*" {
  capabilities       = ["read", "list"]
  required_parameters = ["env"]                      # read must carry ?env=
  allowed_parameters  = { "env" = ["prod", "staging"] }  # value constraint
}
```

The ACL check (`Permissions::check`) reads `env` from `req.data`/`req.body`. At
check time only the seeded query params are present (path captures like `name`
are added later in the route phase), so `allowed_parameters` constrains `env`
without tripping on the secret name.

## Notes / limitations

- Merge is shallow (override keys replace base values wholesale; nested objects
  are not deep-merged).
- Editing an environment in the GUI persists the full effective view as that
  environment's overrides (inherited keys become overrides on save).
- `max_wrapping_ttl` in policies remains unenforced (pre-existing `TODO` in
  `policy.rs`), independent of this feature.
