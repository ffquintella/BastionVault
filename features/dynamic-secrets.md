# Feature: Dynamic Secrets Framework

## Summary

Add a generic **Dynamic Secrets** framework so secret engines can mint short-lived credentials in external systems on demand and revoke them automatically when the lease expires.

This feature ships **only the core services** in-tree: a `DynamicCredentialBackend` trait, a connection-pool / credential-cache layer, lease-manager hooks for `renew` / `revoke`, role-driven generation, the credential audit pipeline, and a thin **plugin host** that wires the framework to the existing BastionVault plugin system ([features/plugin-system.md](plugin-system.md)).

**Concrete engines do not ship in-tree.** PostgreSQL, MySQL, MSSQL, MongoDB, Redis, AWS, GCP, Azure, SSH dynamic-keys, etc. all ship as **dynamic-secret plugins** under a new sibling repository / submodule [`dynamic-engine-plugins/`](../dynamic-engine-plugins/) (mirroring how `plugins-ext/` hosts the reference WASM/process plugins). Operators load only the engines they need at runtime via the plugin catalog (`POST /v1/sys/plugins/catalog/secret/<name>`); BastionVault stays small and the dependency graph for one operator's deployment doesn't include drivers for databases they don't use.

The framework itself is built on the existing pure-Rust stack — no OpenSSL anywhere — and reuses the **lease manager** that already exists for KV-v1 leases ([src/modules/kv/mod.rs:84](../src/modules/kv/mod.rs:84)) and (planned) PKI/SSH-OTP leases.

## Motivation

- **Static credentials are the primary breach vector** in modern attacks. A leaked DB password from a config file is functionally a permanent breach. Dynamic secrets compress that window from "until rotated" to "until lease TTL," which is typically minutes.
- **Vault parity is critical here**: this is *the* feature most customers cite when they say "we use Vault." Without it, BastionVault is a static-secret store, not a Vault replacement.
- **Engine multiplication needs a chassis**: writing five different DB engines + three cloud engines + SSH dynamic mode without a common framework leads to five different lease implementations, three different credential-cache strategies, and an audit pipeline that varies per engine. The framework is the chassis that keeps those engines small and consistent.
- **Plugins, not built-ins, are the right shape for the engine catalog.** A user spinning up BastionVault to mint Postgres credentials should not pay the binary cost of `tiberius` (MSSQL) + `mongodb` + `aws-sdk-iam` + `tokio-postgres` + `sqlx::mysql` + `redis`. Each of those is a substantial dep tree, several with their own TLS stacks. Shipping them as separately-loadable plugins keeps the host binary lean, lets operators audit exactly which target-system code is reachable in their deployment, and avoids the "every dynamic engine that lands forever after is in `cargo build` whether you use it or not" trap.
- **The plugin system already exists** ([features/plugin-system.md](plugin-system.md), shipped through Phase 5): WASM + out-of-process runtimes, capability-gated host imports, signature verification + quarantine, hot-reload locks. Dynamic-secret engines slot into that surface with a small additional capability set (`dynamic_lease_register`, `dynamic_audit_emit`, `dynamic_pool_checkout`) — no new runtime infrastructure needed.
- **Aligns with the lease infrastructure already in place**: BastionVault's KV v1 engine already issues leases with `renew_handler` / `revoke_handler` callbacks (see [src/modules/kv/mod.rs:83](../src/modules/kv/mod.rs:83)). Dynamic secrets generalises that pattern: instead of "renew = re-read storage; revoke = noop," it becomes "renew = call into the plugin's `renew` entrypoint; revoke = call into the plugin's `revoke` entrypoint."

## Current State

- **Lease manager exists** but is exercised only by KV v1 (mostly noop) and the planned PKI/SSH-OTP engines. There is no abstraction for "the secret lives in an external system that we must call out to on revoke."
- **No connection-pool layer exists.** Today a hypothetical DB plugin would have to open a fresh DB connection on every API call, which is unacceptable for both latency and target-side connection-limit reasons. The framework provides the pool; plugins consume it via a host capability rather than embedding their own.
- **No credential-cache layer exists.** Roles like "give me read-only access to db X" are called many times a minute; we need a per-role short-lived cache so identical role calls don't multiply credentials.
- **No central audit pipeline for credential lifecycle.** Audit today logs HTTP requests; dynamic-secret events (`generate`, `extend`, `revoke`, `revoke-failed`) deserve a richer schema (target system, target identity, credential id) so a SOC can answer "what credentials were live in this DB at 14:32 last Tuesday?" in one query.
- The repo's existing engines (`kv`, `kv_v2`, `crypto`, `files`, `resource`, `system`) are all **static** — they store data, they don't mint it. Dynamic secrets is the first engine class where the interesting state lives outside BastionVault.
- **The plugin system is feature-complete** through Phase 5 (publisher signatures, manifest verification, quarantine, hot-reload lock, metrics, process supervisor). What it does *not* yet do is expose dynamic-secret-shaped host capabilities — that's a deliverable of this feature, not a separate plugin-system phase.

## Design

### Split of responsibilities

| Lives in BastionVault (`src/modules/dynamic/`) | Lives in `dynamic-engine-plugins/<engine>/` |
|---|---|
| `DynamicCredentialBackend` trait + ABI                              | One implementation per engine type (postgres, mysql, aws, …) |
| Lease manager hooks (`register`, `renew`, `revoke`, `tidy`)         | `generate` / `renew` / `revoke` / `rotate-root` entrypoints  |
| Connection-pool layer (`deadpool`)                                  | Plugin asks the host for pooled connections via capability   |
| Credential-cache (per-role, per-identity)                           | (none — cache is opaque to plugin)                          |
| Audit pipeline + `dynamic_secret` event schema                       | Plugin emits structured events via `dynamic_audit_emit`      |
| Statement template engine (`{{name}}`, `{{password}}`, …)            | Plugin opts in to the engine for its target language         |
| Plugin catalog wiring (`POST /v1/sys/plugins/catalog/secret/<name>`) | Plugin manifest declares `engine_type = "database"` etc.     |
| HTTP route surface (`/v1/<mount>/{config,roles,creds,...}`)          | Plugin handles the per-route requests routed through the host |

The plugin sees a stable host ABI and a small, audit-able surface. It never opens its own raw TCP connection (the pool gives it back validated connections); it never writes its own audit events (it produces a structured event the host stamps and signs); it never writes its own lease records (the host owns the lease store).

### Core Trait: `DynamicCredentialBackend`

The framework is a thin trait every dynamic engine **plugin** implements. The trait is part of the **dynamic-secrets SDK** (a new crate, `bastion-plugin-dynamic-sdk`, sibling to the existing `bastion-plugin-sdk` already used by `plugins-ext/`):

```rust
#[async_trait]
pub trait DynamicCredentialBackend: Send + Sync {
    /// Engine type name, e.g. "database", "aws".
    fn engine_type(&self) -> &str;

    /// Generate a credential for a role. Returns the credential plus
    /// a backend-defined `internal` blob the framework will hand back
    /// on renew/revoke so the engine doesn't have to look up its own
    /// state.
    async fn generate(
        &self,
        ctx: &DynamicCtx,
        role: &str,
    ) -> Result<DynamicCredential, RvError>;

    /// Extend the credential. May be a no-op for engines that issue
    /// fixed-lifetime credentials (AWS STS sessions, e.g.).
    async fn renew(
        &self,
        ctx: &DynamicCtx,
        secret_internal: &serde_json::Value,
        new_ttl: Duration,
    ) -> Result<(), RvError>;

    /// Drop the credential in the target system.
    async fn revoke(
        &self,
        ctx: &DynamicCtx,
        secret_internal: &serde_json::Value,
    ) -> Result<(), RvError>;

    /// Optional: respond to a `rotate-root` admin call.
    async fn rotate_root(&self, ctx: &DynamicCtx) -> Result<(), RvError> {
        Err(RvError::ErrModuleNotFound)
    }
}

pub struct DynamicCredential {
    pub data: serde_json::Map<String, serde_json::Value>, // returned to caller
    pub internal: serde_json::Value,                       // never returned; passed back on renew/revoke
    pub ttl: Duration,
    pub max_ttl: Duration,
    pub renewable: bool,
}
```

`DynamicCtx` carries a *handle to* the storage view, the audit broadcaster, and the connection pool — never the underlying objects directly, so the plugin can't bypass capability gating. It's the per-call equivalent of the static engines' `Request`.

### Plugin host integration

The framework registers a new plugin **kind**: `secret/dynamic`. A manifest looks like:

```toml
[plugin]
name = "bastion-plugin-postgres"
version = "0.1.0"
kind = "secret/dynamic"
engine_type = "database"          # what mount type this engine claims
runtime = "process"                # or "wasm"

[capabilities]
required = [
  "dynamic_lease_register",
  "dynamic_audit_emit",
  "dynamic_pool_checkout",
  "storage_get",                   # for plugin's per-mount config
  "storage_put",
]
```

When an operator does `vault secrets enable -path=postgres-prod database` (or the BastionVault equivalent), the framework:

1. Resolves `engine_type = "database"` against the catalog,
2. Picks the highest-priority enabled plugin claiming that engine type,
3. Spawns / instantiates the plugin via the existing process / WASM runtime,
4. Routes `/v1/postgres-prod/*` requests to the plugin through the dynamic-host RPC,
5. Mediates lease-manager callbacks back to the plugin on renew/revoke.

The same plugin binary can back many mounts; the same engine type can be served by competing plugins (e.g. `bastion-plugin-postgres` vs. a third-party fork) and the operator picks at mount time.

### Connection Pool Layer

```rust
pub trait ConnectionFactory: Send + Sync {
    type Conn: Send + 'static;
    fn pool_key(&self) -> String;
    async fn connect(&self) -> Result<Self::Conn, RvError>;
    async fn validate(&self, conn: &mut Self::Conn) -> Result<(), RvError>;
}
```

A central `ConnectionPool` (using `deadpool` — pure Rust, MIT) keeps `(target_id, root_credential_version) -> Vec<Conn>` hot inside the **host**, not the plugin. Plugins request a pooled connection via a host capability call (`dynamic_pool_checkout`). This means:

- A single deadpool instance is shared across all mounts of the same target — even if two plugin processes want connections to the same Postgres server, the host hands them sockets out of one pool.
- Plugin restarts don't drain the pool.
- Connection-pool sizing / metrics are an operator concern, not a per-plugin one.

For plugins that genuinely need their own client object (e.g., `aws-sdk-iam` constructs a long-lived client), the SDK exposes a "long-lived handle" capability the plugin owns — but the host is still the one watching for `rotate-root` and signalling the plugin to drop and rebuild.

### Lease Integration

The framework registers each generated credential with the existing lease manager, but with a lifecycle that calls back to the plugin:

1. Plugin's `generate()` returns `DynamicCredential`.
2. The framework wraps it in a `Secret` with `lease_id`, `ttl`, `renewable`, persists `(lease_id, internal_blob, plugin_id, engine_type, role, expires_at)` at `sys/leases/dynamic/<lease_id>` in the barrier.
3. On `PUT /v1/sys/leases/renew`, the lease manager looks up the plugin for `plugin_id` (loading it on demand if currently unloaded) and calls `renew(ctx, internal, new_ttl)`. On success it extends `expires_at`.
4. On `PUT /v1/sys/leases/revoke`, the manager calls `revoke(ctx, internal)`. If the call fails, the lease enters a `revoke-failed` state and a background reaper retries with exponential backoff up to `max_revoke_attempts` (default 6).
5. A periodic `lease_tidy` task scans `sys/leases/dynamic/` and drives any expired-but-not-yet-revoked leases through `revoke`.

Crucially: a lease can outlive a plugin **load**. If the operator unloads the postgres plugin and a lease for it expires, the tidy task **reloads** the plugin to revoke it. The host refuses to silently drop a lease whose plugin it can no longer reach; it surfaces the unhealthy state via `LIST /sys/leases/dynamic/revoke-failed`.

### Roles vs. Targets vs. Connections

Three nouns, kept separate (this is a place where Vault's terminology slip causes confusion):

- **Connection** (or **Target**): a coordinate to an external system — a JDBC URL, an AWS region, a K8s API server. Stored at `<engine>/config/<name>` by the plugin (using its `storage_put` capability). Includes the *root credential* the plugin uses to mint role credentials.
- **Role**: the recipe for generating a credential of a particular flavour against a connection. Stored at `<engine>/roles/<name>`. Includes the connection name, the SQL/IAM/etc. statements to run, default/max TTL, allowed-renewability.
- **Lease**: an instance of a credential generated from a role. Lives in the host-owned lease manager.

A single connection backs many roles; a single role generates many leases.

### Credential-Cache Layer

For high-QPS scenarios the framework offers an opt-in **credential cache**: roles can declare `cache_ttl > 0` to make the framework hand out the same credential to multiple callers within a short window. The cache is keyed by `(role_name, identity_entity_id)` so two different operators never share a credential, but the same operator hammering the role gets a cached secret. Cache entries expire well before the underlying credential's `ttl` so the caller still has time to use it.

Cache lives in the host so a plugin restart doesn't invalidate cached credentials whose target still considers them valid.

Cache is opt-in because for many use cases (DB users, IAM keys), every caller getting a unique identity is a feature, not a cost.

### Audit Schema Extension

A new audit event type `dynamic_secret`:

```json
{
  "type": "dynamic_secret",
  "event": "generate" | "renew" | "revoke" | "revoke_failed",
  "lease_id": "...",
  "engine": "database",
  "plugin": "bastion-plugin-postgres@0.3.1",
  "role": "readonly",
  "connection": "postgres-prod",
  "target_identity": "v-token-readonly-abc123",
  "target_identity_type": "postgres_user",
  "expires_at": "2026-04-25T18:32:11Z",
  "ttl": "30m",
  "actor": { "entity_id": "...", "display_name": "..." },
  "request_id": "..."
}
```

The schema is engine-agnostic but lets a SOC join `target_identity` against external system logs. The credential itself (password, secret-access-key, signed cert) is **never** in this event — it goes into the standard request/response audit with the usual HMAC redaction. The `plugin` field captures the exact plugin + version that produced the event so an audit can trace back to the binary that touched the target.

### Engine Architecture (framework only)

```
src/modules/dynamic/
├── mod.rs                  -- DynamicFramework: registry of mount → plugin bindings
├── backend.rs              -- DynamicCtx, DynamicCredential, common helpers
├── lease.rs                -- Lease lifecycle hooks: register, renew, revoke
├── pool.rs                 -- Host-owned ConnectionPool wrapping `deadpool`
├── cache.rs                -- per-(role, identity) credential cache
├── audit.rs                -- dynamic_secret event emitter
├── tidy.rs                 -- periodic expired-lease sweeper
├── plugin_host.rs          -- bridge to src/plugins/*: spawns dynamic plugins,
│                              dispatches /v1/<mount>/* requests, exposes the
│                              new dynamic_* host capabilities to the plugin
│                              runtime (WASM + process)
└── route.rs                -- generic /config /roles /creds /rotate-root surface
                                that proxies to the bound plugin
```

The host owns the routing: when an operator mounts `bastion-plugin-postgres` at `postgres-prod`, the host registers `/v1/postgres-prod/{config,roles,creds,rotate-root}/...` routes that all go through `route.rs` → `plugin_host.rs` → the running plugin. The plugin sees an RPC call shaped like `{ method: "creds", role: "readonly", ctx: {...} }`, not an HTTP request.

### Plugin SDK

A new sibling crate to the existing `bastion-plugin-sdk`:

```
plugins-ext/                       (existing reference plugins repo, submodule)
├── Cargo.toml                     existing
└── ...

dynamic-engine-plugins/            NEW — separate sibling repo / submodule
├── README.md
├── Cargo.toml                     workspace for the dynamic engines
├── bastion-plugin-dynamic-sdk/    NEW SDK crate, depends on bastion-plugin-sdk
│   ├── src/
│   │   ├── lib.rs                 re-exports
│   │   ├── trait.rs               DynamicCredentialBackend
│   │   ├── ctx.rs                 DynamicCtx (host-handle wrappers)
│   │   ├── pool.rs                connection-pool client (calls dynamic_pool_checkout)
│   │   ├── lease.rs               lease registration helper
│   │   ├── audit.rs               structured event emitter
│   │   ├── statements.rs          {{name}} / {{password}} / {{expiration}} template engine
│   │   └── runtime.rs             plugin-side dispatch loop
├── bastion-plugin-postgres/       Postgres engine plugin (pre-existing reference moves here)
├── bastion-plugin-mysql/          MySQL engine plugin
├── bastion-plugin-mssql/          MSSQL engine plugin
├── bastion-plugin-mongodb/        MongoDB engine plugin
├── bastion-plugin-redis/          Redis engine plugin
├── bastion-plugin-aws/            AWS IAM + STS plugin
├── bastion-plugin-gcp/            GCP service-account plugin
├── bastion-plugin-azure/          Azure SP / app-registration plugin
└── bastion-plugin-ssh-dynamic/    SSH dynamic-keys plugin
```

Each plugin is its own crate, its own binary (process runtime) or WASM module, its own audit trail. The pre-existing `plugins-ext/bastion-plugin-postgres` (a Phase 4 plugin-system reference) is **moved** into `dynamic-engine-plugins/` and rebased on the new dynamic SDK rather than the bare plugin SDK; this is a one-time migration captured in Phase 1 of this feature.

## Implementation Scope

### Phase 1 — Framework + SDK + Postgres reference plugin migration

| Deliverable | Location |
|---|---|
| `src/modules/dynamic/*`           | Framework as above. |
| `src/sys/leases.rs` (extension)   | Hook `dynamic` event-type into the lease manager dispatch. |
| Plugin host capability set        | New `dynamic_lease_register`, `dynamic_audit_emit`, `dynamic_pool_checkout` capabilities surfaced through the existing plugin runtime ([src/plugins/runtime.rs](../src/plugins/runtime.rs)). |
| `dynamic-engine-plugins/bastion-plugin-dynamic-sdk` | The SDK crate. |
| `dynamic-engine-plugins/bastion-plugin-postgres`    | First reference engine. Migrated from `plugins-ext/bastion-plugin-postgres`, rebased on the dynamic SDK. |

In-tree dependencies (host):

```toml
deadpool       = "0.12"        # connection pool (host-owned)
async-trait    = "0.1"
```

The host **does not** pull in `tokio-postgres` / `sqlx` / `tiberius` / `mongodb` / `redis` / `aws-sdk-*`. Those are plugin deps, downstream of the host.

### Phase 2 — MySQL, MSSQL, MongoDB, Redis plugins

Each is its own subdirectory under `dynamic-engine-plugins/`, its own crate, its own binary. Released independently.

### Phase 3 — Cloud plugins (AWS / GCP / Azure)

Same shape — separate plugins under `dynamic-engine-plugins/`. AWS uses the pure-Rust `aws-sdk-iam` / `aws-sdk-sts`; GCP uses `google-cloud-rust`; Azure uses the `azure_*` crate family.

### Phase 4 — SSH dynamic-keys plugin

Hook the `ssh` engine's third historical mode (push key to `authorized_keys` over outbound SSH, return private key, sweep on revoke) into the framework as `bastion-plugin-ssh-dynamic`. The existing in-tree SSH engine ([features/ssh-secret-engine.md](ssh-secret-engine.md)) keeps its CA + OTP + PQC modes; only dynamic-keys is plugin-shaped.

### Phase 5 — GUI Integration

| Deliverable | Location |
|---|---|
| `gui/src/routes/SecretsPage.tsx` (extension) | "Dynamic" tab listing dynamic mounts + roles. |
| `gui/src/components/DynamicCredsModal.tsx`   | "Generate credential" button per role; returns the secret with copy-to-clipboard + countdown timer to TTL. |
| `gui/src/routes/LeasesPage.tsx`              | New page listing live leases with revoke + renew actions. |
| `gui/src/routes/PluginsPage.tsx` (extension) | "Dynamic Engines" filter / catalog browse — install / enable / disable plugins from the UI. |

### Not In Scope

- **OpenLDAP / AD password-rotation engines**. Vault has these but they're "static-secret rotation," not dynamic-secret generation. Already shipped as the in-tree LDAP secret engine ([features/ldap-secret-engine.md](ldap-secret-engine.md)).
- **Kubernetes service-account token engine**. Tracked separately under the (already-mentioned in roadmap) Kubernetes Integration initiative.
- **PKI lease-revocation hooks**. The PKI engine ([features/pki-secret-engine.md](pki-secret-engine.md)) issues certs without leases by design. If we ever add lease-tied PKI certs that auto-revoke on lease expiry, that's a separate optional integration and would itself ship as a plugin.
- **Wrap-response (`wrap_ttl`)**. The Vault response-wrapping pattern is broader than dynamic secrets; if we add it, it'll be a top-level feature, not part of this one.
- **Engines in-tree.** Future requests to "just add MariaDB to BastionVault" are answered by writing a `bastion-plugin-mariadb` plugin, not by amending the host. The host stays small on purpose.

## Testing Requirements

### Unit Tests (host)

- Lease registration → renew → revoke → tidy state machine. Mock plugin that records calls.
- Connection pool: checkout, validate-fail, recycle; max-pool-size enforcement.
- Credential-cache: hit / miss / TTL-expiry / per-identity isolation.
- Audit emitter: every event field is HMAC-redacted by default unless explicitly whitelisted.
- Statement template engine: `{{name}}`, `{{password}}`, `{{expiration}}`, `{{role}}` substitution; SQL-injection-safe quoting.
- Plugin-host bridge: a registered fake plugin receives RPC calls in the right order and gets exactly the host capabilities its manifest asked for; capability requests outside the manifest are denied.
- Lease-outlives-plugin: unload a plugin holding live leases, expire a lease, confirm the host reloads the plugin to revoke it.

### Integration Tests (per plugin, in `dynamic-engine-plugins/<plugin>/tests/`)

Each plugin owns its own integration tests. The host CI runs the framework tests; each plugin's CI runs its own engine-specific tests against testcontainers.

- **Postgres** (testcontainers + `tokio-postgres`): generate a role-based user, connect with the issued credential, run a query that the role's grants permit and one it doesn't (expect denial), revoke, attempt to reconnect (expect `role does not exist`).
- **MySQL** (testcontainers + `sqlx::mysql`): same shape.
- Lease renewal: generate at TTL=10s, renew at T+5s with new_ttl=20s, confirm credential still works at T+15s.
- Revoke-failed retry: simulate a target outage, mark the lease `revoke_failed`, bring the target back, confirm the reaper revokes within `2 * retry_interval`.
- Multi-engine lifecycle: register a `database` and an `aws` engine; lease lookup distinguishes them; revoke-all on a logout cascades correctly.

### Cucumber BDD Scenarios

- Operator installs `bastion-plugin-postgres` from the catalog, configures a Postgres connection + a `readonly` role; an application requests a credential, uses it for 50 minutes, then the lease expires and the user disappears from Postgres.
- Operator runs `rotate-root` on the connection; in-flight leases continue to work (their grants persist), but new generation uses the new root credential.
- Operator force-revokes a lease via `/sys/leases/revoke`; the user is gone from Postgres within seconds and an audit event records the revoke.
- Operator unloads the postgres plugin while leases are live; the next `/sys/leases/tidy` run reloads it transparently to revoke expired leases.

### Negative Tests

- Generating a credential against a role whose connection's root credential has been revoked: clear error, no credential returned, no orphaned target user.
- Renew on a non-renewable lease: rejected.
- Renew past `max_ttl`: clamped to `max_ttl`.
- Concurrent revoke + renew on the same lease: one wins, the other gets a deterministic `LeaseAlreadyRevoked` / `LeaseAlreadyRenewed` error — no orphaned target identity.
- A plugin manifest requesting a capability it doesn't need: load is refused with a clear error (capability minimisation enforced).
- A plugin attempting an out-of-manifest host call at runtime: refused; event audit'd; plugin marked unhealthy.

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`** in the host: same constraint as PKI / Transit / TOTP / SSH. Plugins inherit the constraint by convention; a plugin that pulls in `openssl-sys` will not be accepted into `dynamic-engine-plugins/`. Out-of-tree plugins are operator-vetted.
- **Plugin signature verification** is mandatory: the existing publisher-signature gate ([src/plugins/verifier.rs](../src/plugins/verifier.rs)) refuses to load a dynamic-engine plugin without a signed manifest. Operators can enable an `unsigned` allow-list for development, same as today.
- **Capability minimisation**: the dynamic-host capabilities (`dynamic_lease_register`, `dynamic_audit_emit`, `dynamic_pool_checkout`) are the only new gates. No plugin gets `network_outbound` directly — it requests pooled connections via the pool capability so the host can rate-limit, audit, and rotate roots.
- **Root credential storage**: the per-connection root credential is the single most sensitive item the framework persists. It lives barrier-encrypted at `<engine>/config/<name>/root` and is *never* returned by `GET /v1/<engine>/config/<name>` — only metadata is. `rotate-root` is the supported way to change it; post-rotation the old credential is best-effort revoked in the target.
- **Statement templating** runs **in the host**, not the plugin. The plugin supplies a template; the host expands it. The host refuses to expand any token that isn't in a fixed allowlist (`{{name}}`, `{{password}}`, `{{expiration}}`, `{{role}}`, `{{display_name}}`, `{{entity_id}}`). This is the single most security-critical bit of the surface and we keep it on the trust side.
- **Generated identity entropy**: usernames are derived from `v-<token-display>-<role>-<timestamp>-<8-hex>` (Vault-compatible). Passwords are 24 bytes from `OsRng`, rendered as URL-safe base64 (32 chars). Generation happens **in the host** so a malicious plugin cannot supply weak credentials and hand them out as if they were strong.
- **Constant-time compare**: where the framework holds a credential to verify against (rare — mostly cloud engines do this server-side), comparisons go through `subtle::ConstantTimeEq`.
- **Connection-pool isolation**: per-connection pools are keyed by `(connection_name, root_credential_version)` and live in the host. After `rotate-root`, the old pool drains and is replaced — no stale-credential connections survive a rotation. Plugins cannot bypass the pool to open a raw socket with cached root creds.
- **Revoke-failed quarantine**: if the plugin's `revoke()` fails, the lease enters `revoke_failed` state with the plugin's last error captured. Operators can list these via `LIST /sys/leases/dynamic/revoke-failed` and force-clear after manual cleanup. The framework refuses to silently drop a lease whose target it could not clean up.
- **Audit completeness**: the framework guarantees every `generate` event has a paired `revoke` (or `revoke_failed`) event. A missing `revoke` event is itself an audit signal that something went wrong.
- **TLS verification**: every target connection verifies the server certificate against the system trust store (or an operator-supplied CA per connection) by default. `insecure_skip_tls_verify` exists for development only and is logged at WARN every time a connection uses it. The pool is the chokepoint that enforces this — a plugin cannot turn off verification on its own.
- **Plugin process isolation**: process-runtime plugins run as separate OS processes under the existing supervisor ([src/plugins/process_supervisor.rs](../src/plugins/process_supervisor.rs)). A plugin crash does not take down the host. WASM-runtime plugins are sandboxed by `wasmtime` capability gating.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md), and this file's "Current State" / phase markers. Plugin releases under `dynamic-engine-plugins/` track their own versions; the host CHANGELOG records "framework supports plugin X starting at version Y," not the per-plugin release notes.
