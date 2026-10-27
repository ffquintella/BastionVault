# BastionVault Dynamic-Secret Engine Plugins

This directory hosts the **dynamic-secret engine plugins** for BastionVault. The host ships only the dynamic-secrets *framework* (lease manager, connection-pool grants, audit pipeline, plugin host bridge, credential generation and statement templating); concrete engines for PostgreSQL, MySQL, MSSQL, MongoDB, Redis, AWS, GCP, Azure, SSH dynamic-keys, etc. live here as separately loadable plugins that the operator registers and mounts.

See the full design at [`features/dynamic-secrets.md`](../features/dynamic-secrets.md) (T62).

## Why plugins, not built-ins

A user spinning up BastionVault to mint Postgres credentials should not pay the binary cost of `tiberius` (MSSQL) + `mongodb` + `aws-sdk-iam` + `tokio-postgres` + `sqlx::mysql` + `redis`. Each is a substantial dep tree, several with their own TLS stacks. Shipping engines as separately loadable plugins keeps the host binary lean, lets operators audit exactly which target-system code is reachable in their deployment, and avoids the "every dynamic engine that lands forever after is in `cargo build` whether you use it or not" trap.

The plugin system already exists ([`features/plugin-system.md`](../features/plugin-system.md)): WASM + out-of-process runtimes, capability-gated host imports, signature verification + quarantine, hot-reload locks, process supervisor, plugin catalog, and metrics. **Dynamic-secret engine plugins reuse all of it unchanged** — they declare `plugin_type = "secret/dynamic"` and an `engine_type` in the existing manifest schema (ABI 1.5), request the dynamic host capabilities (`dynamic_lease_register`, `dynamic_audit_emit`, `dynamic_pool_checkout`) through the existing capability gate, and otherwise behave exactly like any plugin in [`plugins-ext/`](../plugins-ext/).

## Layout

```
dynamic-engine-plugins/
├── README.md                          this file
├── Cargo.toml                         separate workspace (own target/, excluded from the host's)
├── bastion-plugin-dynamic-sdk/        SDK every dynamic plugin depends on
├── bastion-plugin-dynamic-fixture/    test fixture: a fake engine run through the testkit (never shipped)
└── bastion-plugin-postgres/           PostgreSQL dynamic users (process runtime)
```

Planned, each its own crate and artefact: MySQL, MSSQL, MongoDB, Redis (Phase 2), AWS / GCP / Azure (Phase 3), SSH dynamic keys (Phase 4).

## Status

- `bastion-plugin-dynamic-sdk` 0.1.0 and `bastion-plugin-postgres` 0.2.0 are in place (`publish = false` until ABI 1.5 ships in a stable host release).
- The Postgres plugin is the Phase 4 reference plugin, rebased on the dynamic SDK. The old non-dynamic copy was removed from the `plugins-ext` submodule (commit `85168b8`); this crate is the only Postgres plugin.
- The live-database test is ignored by default and starts its own container (see *Building, testing, packing and signing*).

## How a dynamic plugin works

The host does everything security-critical; the plugin only talks to its target.

1. `roles/<name>` and `config/<name>` writes are proxied to the plugin as `{op, path, data}`. The SDK stores them in the plugin's storage (`storage_prefix = ""`). A connection's secret fields (the root password) are stored barrier-encrypted by the host and never read back; `config/<name>` reads answer settings and `allowed_roles` only. The host keeps the TLS policy (`tls_ca_pem`, `insecure_skip_tls_verify`) itself.
2. `creds/<role>`: the host asks `dynamic.role` for the recipe (the SDK refuses a role its connection's `allowed_roles` does not admit; empty admits none, `*` all), checks the templates, **generates the username and password**, renders the statements and sends `dynamic.generate`. The plugin runs them, and the SDK registers the lease with `dynamic_lease_register` **exactly once, after** the backend succeeded. A generate that ends without a lease is revoked by the host.
3. Renew and revoke come back as `dynamic.renew` / `dynamic.revoke` with rendered statements and the lease's `internal` blob. A revoke must succeed when the identity is already gone.
4. `rotate-root/<connection>`: the host generates the new root secret and sends it in `dynamic.rotate_root`; the plugin sets it on the target and stores it.

A plugin never generates, logs or returns a credential. In the SDK, credentials are `SecretString` (no `Display`/`Serialize`, redacted `Debug`, wiped on drop), error text is redacted before it leaves, and a reply, lease blob or audit label carrying a known secret is refused.

## Contributing a new engine

1. Copy `bastion-plugin-postgres/` as a template.
2. Implement `DynamicCredentialBackend` (`generate`, `renew`, `revoke`, optional `rotate_root`) and its `connection_schema` from `bastion-plugin-dynamic-sdk`. Dial the target only after `ctx.pool_checkout(...)`, with exactly the grant's TLS policy.
3. `main` is `bastion_plugin_dynamic_sdk::process::run_main(MyBackend::new())`; a WASM engine uses `dynamic_module!(MyBackend, MyBackend::new())` and builds with `--features wasm` for `wasm32-unknown-unknown` (it cannot await real I/O).
4. In `plugin.toml`: `plugin_type = "secret/dynamic"`, `engine_type` (`database`, `aws`, `gcp`, `azure` or `ssh`), `abi_version = "1.5"` (a 1.4 host, i.e. 0.45.9, does not know this plugin kind), and only the capabilities you use — the host refuses `allowed_hosts`, `app.net`, entity storage, credential providers and the SQL browser's `sql_gate` / `resource_credentials` / `sql_console` for this kind.
5. Unit-test against `bastion_plugin_dynamic_sdk::testing::MockHost` and run the built binary through `bastion-plugin-testkit` (`invoke_process_dynamic`); ship an integration test against the target system.
6. No `openssl-sys` / `aws-lc-sys` (`make dynamic-plugins-test` checks the whole workspace). rustls goes on the `ring` provider.

## Building, testing, packing and signing

```bash
# from the host repo root
make dynamic-plugins-test     # unit tests, testkit process + WASM runs, dependency ban

cd dynamic-engine-plugins
cargo build --release -p bastion-plugin-postgres
# artifact: target/release/bastion-plugin-postgres(.exe)
```

Live PostgreSQL test (development only, plaintext through the host's insecure policy). It starts its own `postgres:16` container through `docker` or `podman` (random port on 127.0.0.1, random root password, always removed afterwards, also on a panic), so no server or env vars are needed:

```bash
make dynamic-plugins-live     # not part of dynamic-plugins-test: it pulls and runs an image
# or: cd dynamic-engine-plugins && cargo test -p bastion-plugin-postgres --test live -- --ignored
```

`BV_TEST_CONTAINER_ENGINE=docker|podman` forces an engine. With no usable engine the test is skipped with a message; `BV_TEST_REQUIRE_CONTAINER=1` makes that a failure instead. To use an external server, set `BV_TEST_POSTGRES_URL`, `BV_TEST_POSTGRES_USER` and `BV_TEST_POSTGRES_PASSWORD`. The container helper is `bastion-plugin-postgres/tests/support/container.rs`, reusable by other engines' live tests. CI does not run this test: it would need a runner with a container engine (e.g. `ubuntu-latest`, which ships Docker) and a job calling `make dynamic-plugins-live` with `BV_TEST_REQUIRE_CONTAINER=1`.

Pack and sign with the same tool and keys as `plugins-ext` (`crates/bv-plugin-pack`; `make plugins-keygen` mints a dev ML-DSA-65 key):

```bash
make plugins-pack-build       # builds ./target-plugin-pack/release/bv-plugin-pack
./target-plugin-pack/release/bv-plugin-pack \
  --manifest          dynamic-engine-plugins/bastion-plugin-postgres/plugin.toml \
  --binary            dynamic-engine-plugins/target/release/bastion-plugin-postgres \
  --out               bastion-plugin-postgres.bvplugin \
  --signing-seed-file plugins-ext/dist/hml-signing-key.seed \
  --signing-key-name  bastionvault-hml
```

Register the bundle through the plugin catalog like any process plugin, then mount it (`type = "plugin:bastion-plugin-postgres"`) and configure it:

```bash
bvault write postgres/config/prod connection_url='postgres://db.internal:5432/app' \
  username=vault password=... allowed_roles=readonly tls_ca_pem="$(cat ca.pem)"
bvault write postgres/roles/readonly connection=prod default_ttl=1h max_ttl=24h \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\""
bvault read postgres/creds/readonly
```

`connection_url` may not carry a user or password (a config read returns it). Without `tls_ca_pem` the OS trust store is used; TLS is required unless the operator sets `insecure_skip_tls_verify` (development only). Empty revocation statements mean `DROP OWNED BY` + `DROP ROLE IF EXISTS`; empty renew statements mean `ALTER ROLE … VALID UNTIL`. A role may set `cache_ttl` (e.g. `30s`, at most 300 s, default off) to let the host hand the same credential back to the same identity within that window (see `docs/api.md` § Dynamic-secret plugin mounts); the plugin is not involved.

A dynamic plugin's own storage (`config/`, `roles/`) is per mount: mounting one plugin twice gives two independent sets.

## Distribution

This directory is intended to become its own git repository, mounted as a submodule under the host repo at `<host>/dynamic-engine-plugins/`, mirroring `plugins-ext/`. Each plugin is versioned and released independently; the host CHANGELOG records "framework supports plugin X starting at version Y", not per-plugin release notes.
