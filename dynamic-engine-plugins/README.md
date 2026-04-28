# BastionVault Dynamic-Secret Engine Plugins

This directory hosts the **dynamic-secret engine plugins** for BastionVault. The host crate ships only the dynamic-secrets *framework* (lease manager, connection pool, credential cache, audit pipeline, plugin host bridge); concrete engines for PostgreSQL, MySQL, MSSQL, MongoDB, Redis, AWS, GCP, Azure, SSH dynamic-keys, etc. live here as separately-loadable plugins and are loaded on demand by the operator at mount time.

See the full design at [`features/dynamic-secrets.md`](../features/dynamic-secrets.md).

## Why plugins, not built-ins

A user spinning up BastionVault to mint Postgres credentials should not pay the binary cost of `tiberius` (MSSQL) + `mongodb` + `aws-sdk-iam` + `tokio-postgres` + `sqlx::mysql` + `redis`. Each is a substantial dep tree, several with their own TLS stacks. Shipping engines as separately-loadable plugins keeps the host binary lean, lets operators audit exactly which target-system code is reachable in their deployment, and avoids the "every dynamic engine that lands forever after is in `cargo build` whether you use it or not" trap.

The plugin system already exists ([`features/plugin-system.md`](../features/plugin-system.md), shipped through Phase 5): WASM + out-of-process runtimes, capability-gated host imports, signature verification + quarantine, hot-reload locks. Dynamic-secret engines slot in through a small additional capability set — no new runtime infrastructure needed.

## Layout

```
dynamic-engine-plugins/
├── README.md                       this file
├── Cargo.toml                      workspace
├── bastion-plugin-dynamic-sdk/     SDK crate every dynamic plugin depends on
├── bastion-plugin-postgres/        Postgres dynamic users
├── bastion-plugin-mysql/           MySQL dynamic users
├── bastion-plugin-mssql/           MSSQL dynamic logins
├── bastion-plugin-mongodb/         MongoDB dynamic users
├── bastion-plugin-redis/           Redis ACL dynamic users
├── bastion-plugin-aws/             AWS IAM users + STS sessions
├── bastion-plugin-gcp/             GCP service-account keys
├── bastion-plugin-azure/           Azure SP / app-registration credentials
└── bastion-plugin-ssh-dynamic/     SSH dynamic-keys mode (push to authorized_keys)
```

Each plugin is its own crate, its own binary (process runtime) or WASM module, its own audit trail. Each ships with its own integration tests against testcontainers / cloud emulators and is released independently.

## Status

Empty placeholder pending Phase 1 of the Dynamic Secrets framework. When Phase 1 lands:

1. The framework + dynamic-host capabilities ship in the BastionVault host crate.
2. `bastion-plugin-dynamic-sdk` ships as the first directory here.
3. The pre-existing `plugins-ext/bastion-plugin-postgres` (a Phase 4 plugin-system reference) is migrated into `dynamic-engine-plugins/bastion-plugin-postgres` and rebased on the dynamic SDK.

Subsequent phases add the remaining engines listed above.

## Distribution

This directory is intended to be its own git repository, mounted as a submodule under the host repo at `<host>/dynamic-engine-plugins/`, mirroring how [`plugins-ext/`](../plugins-ext/) hosts the reference plugin-system plugins.

```bash
# from the host repo, once Phase 1 lands:
git submodule add <repo-url> dynamic-engine-plugins
git submodule update --init dynamic-engine-plugins
```

Operators install individual plugins from a release artifact via the existing plugin catalog:

```bash
bvault sys plugins catalog secret bastion-plugin-postgres \
  --sha256 <hex> \
  --command bastion-plugin-postgres
bvault secrets enable -path=postgres-prod -plugin=bastion-plugin-postgres database
```

## Building

(Once plugins exist — placeholder for the workflow.)

```bash
# Build a process plugin
cargo build --release -p bastion-plugin-postgres
# artifact: target/release/bastion-plugin-postgres(.exe)

# Build a WASM plugin (when applicable)
rustup target add wasm32-wasip1
cargo build --release --target wasm32-wasip1 -p bastion-plugin-aws
# artifact: target/wasm32-wasip1/release/bastion_plugin_aws.wasm
```

## Contributing a new engine

1. Copy `bastion-plugin-postgres/` as a template.
2. Implement `DynamicCredentialBackend` from `bastion-plugin-dynamic-sdk`.
3. Declare your manifest's `kind = "secret/dynamic"` and `engine_type = "<your engine>"`.
4. Request only the host capabilities you need — the host enforces minimisation.
5. Ship integration tests against the target system (testcontainers preferred).
6. Sign the artifact with your publisher key per the plugin-system signing requirements.

The host's CI gates accept new plugins only when the manifest is signed, the integration tests pass against a pinned version of the target system, and the plugin pulls no `openssl-sys` / `aws-lc-sys`.
