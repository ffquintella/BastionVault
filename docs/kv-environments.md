# Per-Environment KV v2 Secrets

A single KV v2 secret can hold a shared **base** key/value set plus per-**environment**
override sets. A read selects an environment and receives the *merge* of the base
with that environment's overrides. This lets you model the same logical secret
(a DB connection string, an API base URL, a feature-flag bag) across `prod`,
`staging`, and `dev` from **one policy-gated path** instead of duplicating the
shared keys across sibling paths like `secret/app/prod/db` and
`secret/app/staging/db`.

> Applies to **KV v2** mounts only (`kv-v2`). Plain `kv` (v1) secrets ignore the
> `env` selector entirely.

## Model

A versioned secret stores two things:

- **`data`** — the shared **base** set, present on every read.
- **`envs`** — a map of environment name → override set (`{ "prod": {...}, "staging": {...} }`).

A read with `?env=prod` returns `merge(base, envs["prod"])`. The merge is
**shallow and override-wins**: a key present in the environment overrides replaces
the base value wholesale (nested objects are not deep-merged). Keys only in the
base are inherited; keys only in the override are added.

```
base            = { host: "db.internal", port: "5432", pool: "10" }
envs["prod"]    = { host: "db.prod.internal", pool: "50" }

read ?env=prod  → { host: "db.prod.internal", port: "5432", pool: "50" }
                       └ override         └ inherited        └ override
```

### Resolution rules

| Request | Secret has `envs`? | Result |
|---|---|---|
| no `env` | — | base `data` only |
| `?env=prod`, `prod` declared | yes | `merge(base, envs[prod])` |
| `?env=prod`, `prod` **not** declared | yes | **404** (strict miss) |
| `?env=prod` | no `envs` (legacy/plain secret) | base `data`; `env` ignored |

Every successful read carries two extra metadata fields:

- **`resolved_env`** — the environment actually applied (or `null` for base).
- **`available_envs`** — the environments declared on this secret.

## HTTP API

### Read

```
GET /v1/<mount>/data/<path>?env=<name>
```

`env` (and `version`) are lifted from the query string into the request data
*before* the ACL check, so a policy can require and constrain `env`. Response:

```json
{
  "data": { "host": "db.prod.internal", "port": "5432", "pool": "50" },
  "metadata": {
    "version": 7,
    "resolved_env": "prod",
    "available_envs": ["prod", "staging"]
  }
}
```

### Write

Three modes, distinguished by the request body:

**Targeted single-environment patch** — writes overrides for one environment;
the base and all other environments are carried forward into the new version.

```json
POST /v1/<mount>/data/<path>
{ "env": "prod", "data": { "host": "db.prod.internal", "pool": "50" } }
```

**Full multi-environment write** — replaces base and the full env map at once.

```json
POST /v1/<mount>/data/<path>
{
  "data":  { "host": "db.internal", "port": "5432", "pool": "10" },
  "envs":  { "prod": { "host": "db.prod.internal", "pool": "50" },
             "staging": { "host": "db.staging.internal" } }
}
```

**Legacy base-only write** — sets only the base; existing `envs` are preserved.

```json
POST /v1/<mount>/data/<path>
{ "data": { "host": "db.internal", "port": "5432" } }
```

> Sending `env` **and** `envs` in the same body is rejected. CAS (`options.cas`)
> and version pruning behave exactly as in standard KV v2.

### Environment registry (advisory)

A mount can declare a suggested list of environment names. This is **advisory**
— it populates the GUI dropdown and documents intent; free-form environment
names are still accepted on reads and writes. Names must be non-empty and contain
no `/` or control characters.

```json
POST /v1/<mount>/config
{ "environments": ["prod", "staging", "dev"] }
```

## CLI

### Read an environment

```bash
bvault read --env prod secret/apps/netrisk/db
```

`--env` appends `?env=<name>` to the request. Required when the secret's policy
lists `env` under `required_parameters`. Combine with `--field` / `--format` as
usual:

```bash
bvault read --env prod --field=host secret/apps/netrisk/db
bvault read --env staging --format=json secret/apps/netrisk/db
```

### Write an environment override

```bash
bvault write --env prod secret/apps/netrisk/db host=db.prod.internal pool=50
```

With `--env`, the `key=value` pairs are written as that environment's overrides
only — the base values and other environments are preserved (targeted-patch
mode). Without `--env`, you write the base set as normal:

```bash
bvault write secret/apps/netrisk/db host=db.internal port=5432 pool=10
```

The standard value sources apply: `key=@file`, `key=-` (stdin).

## GUI

On a **KV v2** mount, the secret detail view in the **Secrets** page gains an
environment workflow:

- **Environment selector** — a dropdown at the top of the detail view switches
  between **base (shared)** and any declared environment. Selecting one re-reads
  the secret with that `env` and shows the merged effective values. A
  `base + <env> overrides` badge marks the active environment.
- **Inherited / override badges** — in an environment view, each key is tagged
  **inherited** (comes from the base) or **override** (set for this environment).
- **Editing an environment** — saving while an environment is selected persists
  the edited pairs as *that environment's overrides*. Note that the full
  effective view is saved as overrides, so **inherited keys become explicit
  overrides on save**.
- **Create modal** — the *New Secret* form has an optional **Environment** field.
  Leave it blank to create the base/shared secret; fill it to create the secret
  with an initial environment override set.
- **Engine config** — the KV v2 engine-config editor exposes the advisory
  **environments** registry, which feeds the selector's dropdown.

The GUI routes environment writes through the `write_secret_env` backend command,
which works in both embedded and remote modes.

## Policy interplay

Per-environment secrets are what finally make `required_parameters = ["env"]`
enforceable on KV reads — the `env` selector is carried into the request data
before the ACL check runs.

```hcl
path "secret/data/apps/netrisk/*" {
  capabilities        = ["read", "list"]
  required_parameters = ["env"]                          # read MUST carry ?env=
  allowed_parameters  = { "env" = ["prod", "staging"] }  # constrain the value
}
```

- `required_parameters = ["env"]` — a read without `?env=` is denied.
- `allowed_parameters = { "env" = ["prod", "staging"] }` — only those values are
  permitted; `?env=dev` is denied.

At ACL-check time only the seeded query params are present (path captures like the
secret name are merged in later), so `allowed_parameters` constrains `env`
without tripping on the secret name.

### Policy builder

In the GUI policy builder (`PolicyBlockEditor`), each rule has a **"Restrict to
environments"** field. Entering a comma-separated list emits the
`required_parameters` + `allowed_parameters` pair above, and round-trips cleanly
through the HCL source tab.

## Notes & limitations

- The merge is **shallow** — override keys replace base values wholesale; nested
  objects are not deep-merged.
- Editing an environment in the GUI persists the full effective view as that
  environment's overrides (inherited keys become overrides on save).
- The environment registry on a mount is advisory only; free-form names are
  accepted everywhere.
- The `env` selector is folded into audit log entries verbatim (it is a
  non-secret request parameter, not HMAC'd).
