# Feature: Dynamic Secrets Framework

## Summary

Add a generic **Dynamic Secrets** framework so secret engines can mint short-lived credentials in external systems on demand and revoke them automatically when the lease expires. The framework itself is engine-agnostic plumbing: a `DynamicCredentialBackend` trait, a connection-pool/credential-cache layer, lease-manager hooks for `renew` / `revoke`, role-driven generation, and a credential audit pipeline.

Concrete engines that consume the framework ship as separate features:

- **`database/`** -- PostgreSQL, MySQL, MSSQL, MongoDB, Redis dynamic users (Phase 1 deliverable).
- **`aws/`** -- IAM users + STS sessions (Phase 2).
- **`gcp/`** / **`azure/`** -- service accounts / app-registration credentials (Phase 3).
- **`ssh/` dynamic-keys mode** -- the third Vault SSH mode, deferred from [features/ssh-secret-engine.md](ssh-secret-engine.md) (Phase 4).
- **`pki/` short-lived leaves with auto-revocation** -- optional integration once the PKI engine ([features/pki-secret-engine.md](pki-secret-engine.md)) ships (Phase 5).

The framework is built on the existing pure-Rust stack -- no OpenSSL anywhere -- and reuses the **lease manager** that already exists for KV-v1 leases ([src/modules/kv/mod.rs:84](../src/modules/kv/mod.rs:84)) and (planned) PKI/SSH-OTP leases.

## Motivation

- **Static credentials are the primary breach vector** in modern attacks. A leaked DB password from a config file is functionally a permanent breach. Dynamic secrets compress that window from "until rotated" to "until lease TTL," which is typically minutes.
- **Vault parity is critical here**: this is *the* feature most customers cite when they say "we use Vault." Without it, BastionVault is a static-secret store, not a Vault replacement.
- **Engine multiplication needs a chassis**: writing five different DB engines + three cloud engines + SSH dynamic mode without a common framework leads to five different lease implementations, three different credential-cache strategies, and an audit pipeline that varies per engine. The framework is the chassis that keeps those engines small and consistent.
- **Aligns with the lease infrastructure already in place**: BastionVault's KV v1 engine already issues leases with `renew_handler` / `revoke_handler` callbacks (see [src/modules/kv/mod.rs:83](../src/modules/kv/mod.rs:83)). Dynamic secrets generalises that pattern: instead of "renew = re-read storage; revoke = noop," it becomes "renew = extend the credential's expiry in the target system; revoke = drop the user/key/token in the target system."

## Current State

- **Lease manager exists** but is exercised only by KV v1 (mostly noop) and the planned PKI/SSH-OTP engines. There is no abstraction for "the secret lives in an external system that we must call out to on revoke."
- **No connection-pool layer exists.** Today a hypothetical DB engine would have to open a fresh DB connection on every API call, which is unacceptable for both latency and target-side connection-limit reasons.
- **No credential-cache layer exists.** Roles like "give me read-only access to db X" are called many times a minute; we need a per-role short-lived cache so identical role calls don't multiply credentials.
- **No central audit pipeline for credential lifecycle.** Audit today logs HTTP requests; dynamic-secret events (`generate`, `extend`, `revoke`, `revoke-failed`) deserve a richer schema (target system, target identity, credential id) so a SOC can answer "what credentials were live in this DB at 14:32 last Tuesday?" in one query.
- The repo's existing engines (`kv`, `kv_v2`, `crypto`, `files`, `resource`, `system`) are all **static** -- they store data, they don't mint it. Dynamic secrets is the first engine class where the interesting state lives outside BastionVault.

## Design

### Core Trait: `DynamicCredentialBackend`

The framework is a thin trait every dynamic engine implements:

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

`DynamicCtx` carries the storage view, the audit broadcaster, the connection pool, and the role's parsed config. It's the per-call equivalent of the static engines' `Request`.

### Connection Pool Layer

```rust
pub trait ConnectionFactory: Send + Sync {
    type Conn: Send + 'static;
    fn pool_key(&self) -> String;
    async fn connect(&self) -> Result<Self::Conn, RvError>;
    async fn validate(&self, conn: &mut Self::Conn) -> Result<(), RvError>;
}
```

A central `ConnectionPool` (using `deadpool` -- pure Rust, MIT) keeps `(target_id, root_credential_version) -> Vec<Conn>` hot. Pools are sized per target with a 30s idle timeout and a connection-validate-on-checkout. Reusing an existing connection-pool crate avoids a class of bugs we don't want to write ourselves.

### Lease Integration

The framework registers each generated credential with the existing lease manager, but with a lifecycle that calls back to the engine:

1. `generate()` returns `DynamicCredential`.
2. The framework wraps it in a `Secret` with `lease_id`, `ttl`, `renewable`, persists `(lease_id, internal_blob, engine_type, role, expires_at)` at `sys/leases/dynamic/<lease_id>` in the barrier.
3. On `PUT /v1/sys/leases/renew`, the lease manager looks up the engine for `engine_type` and calls `renew(ctx, internal, new_ttl)`. On success it extends `expires_at`.
4. On `PUT /v1/sys/leases/revoke`, the manager calls `revoke(ctx, internal)`. If the call fails, the lease enters a `revoke-failed` state and a background reaper retries with exponential backoff up to `max_revoke_attempts` (default 6).
5. A periodic `lease_tidy` task scans `sys/leases/dynamic/` and drives any expired-but-not-yet-revoked leases through `revoke`.

This pattern is the same one Vault uses; the value of writing it into a generic framework is that every engine inherits it for free.

### Roles vs. Targets vs. Connections

Three nouns, kept separate (this is a place where Vault's terminology slip causes confusion):

- **Connection** (or **Target**): a coordinate to an external system -- a JDBC URL, an AWS region, a K8s API server. Stored at `<engine>/config/<name>`. Includes the *root credential* the engine uses to mint role credentials.
- **Role**: the recipe for generating a credential of a particular flavour against a connection. Stored at `<engine>/roles/<name>`. Includes the connection name, the SQL/IAM/etc. statements to run, default/max TTL, allowed-renewability.
- **Lease**: an instance of a credential generated from a role. Lives in the lease manager.

A single connection backs many roles; a single role generates many leases.

### Credential-Cache Layer

For high-QPS scenarios the framework offers an opt-in **credential cache**: roles can declare `cache_ttl > 0` to make the framework hand out the same credential to multiple callers within a short window. The cache is keyed by `(role_name, identity_entity_id)` so two different operators never share a credential, but the same operator hammering the role gets a cached secret. Cache entries expire well before the underlying credential's `ttl` so the caller still has time to use it.

Cache is opt-in because for many use cases (DB users, IAM keys), every caller getting a unique identity is a feature, not a cost.

### Audit Schema Extension

A new audit event type `dynamic_secret`:

```json
{
  "type": "dynamic_secret",
  "event": "generate" | "renew" | "revoke" | "revoke_failed",
  "lease_id": "...",
  "engine": "database",
  "role": "readonly",
  "connection": "postgres-prod",
  "target_identity": "v-token-readonly-abc123",      // username, ARN, key_id, ...
  "target_identity_type": "postgres_user",
  "expires_at": "2026-04-25T18:32:11Z",
  "ttl": "30m",
  "actor": { "entity_id": "...", "display_name": "..." },
  "request_id": "..."
}
```

The schema is engine-agnostic but lets a SOC join `target_identity` against external system logs. The credential itself (password, secret-access-key, signed cert) is **never** in this event -- it goes into the standard request/response audit with the usual HMAC redaction.

### Engine Architecture (framework only)

```
src/modules/dynamic/
├── mod.rs                  -- DynamicFramework: registry of DynamicCredentialBackends
├── backend.rs              -- DynamicCtx, DynamicCredential, common helpers
├── lease.rs                -- Lease lifecycle hooks: register, renew, revoke
├── pool.rs                 -- ConnectionPool wrapping `deadpool`
├── cache.rs                -- per-(role, identity) credential cache
├── audit.rs                -- dynamic_secret event emitter
└── tidy.rs                 -- periodic expired-lease sweeper
```

Concrete engines (database, aws, ...) live in their own `src/modules/<name>/` directories and call into `crate::modules::dynamic::*`.

### Database Engine (Phase 1 deliverable)

```
src/modules/database/
├── mod.rs                  -- registers "database" backend
├── path_config.rs          -- /v1/database/config/:name
├── path_roles.rs           -- /v1/database/roles/:name
├── path_creds.rs           -- /v1/database/creds/:role
├── path_rotate_root.rs     -- /v1/database/rotate-root/:name
├── plugins/
│   ├── postgres.rs         -- using `tokio-postgres` or `sqlx::postgres`
│   ├── mysql.rs            -- using `sqlx::mysql`
│   ├── mssql.rs            -- using `tiberius`
│   ├── mongodb.rs          -- using `mongodb` (BSON, Tokio)
│   └── redis.rs            -- using `redis` (Tokio)
└── statements.rs           -- SQL/cmd template engine for `creation_statements`, `revocation_statements`, etc.
```

All target-system clients are pure-Rust (`tokio-postgres`, `sqlx`, `tiberius`, `mongodb`, `redis`). No OpenSSL.

A `database` role looks like:

```hcl
db_name           = "postgres-prod"
default_ttl       = "1h"
max_ttl           = "24h"
creation_statements = <<EOT
  CREATE ROLE "{{name}}" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';
  GRANT SELECT ON ALL TABLES IN SCHEMA public TO "{{name}}";
EOT
revocation_statements = <<EOT
  REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM "{{name}}";
  DROP ROLE "{{name}}";
EOT
renew_statements = <<EOT
  ALTER ROLE "{{name}}" VALID UNTIL '{{expiration}}';
EOT
```

This is intentional Vault-syntax compatibility; an operator's existing Vault `database/roles/*` configs migrate by changing the URL.

## Implementation Scope

### Phase 1 -- Framework + Database Engine (Postgres / MySQL)

| File | Purpose |
|---|---|
| `src/modules/dynamic/*` | Framework as above. |
| `src/modules/database/*` | Database engine; Postgres + MySQL plugins only. |
| `src/sys/leases.rs` (extension) | Hook `dynamic` event-type into the lease manager dispatch. |

Dependencies:

```toml
deadpool       = "0.12"
tokio-postgres = "0.7"          # Postgres
rustls         = { ... }        # already in tree; tokio-postgres uses rustls feature
sqlx           = { version = "0.8", default-features = false, features = ["runtime-tokio", "tls-rustls", "postgres", "mysql"] }
async-trait    = "0.1"
```

### Phase 2 -- MSSQL, MongoDB, Redis Plugins

| File | Purpose |
|---|---|
| `src/modules/database/plugins/mssql.rs` | `tiberius` MSSQL client. |
| `src/modules/database/plugins/mongodb.rs` | `mongodb` driver. |
| `src/modules/database/plugins/redis.rs` | `redis` (ACL-based dynamic users). |

### Phase 3 -- AWS / GCP / Azure Engines

| File | Purpose |
|---|---|
| `src/modules/aws/*` | IAM user + STS engines using `aws-sdk-iam` / `aws-sdk-sts` (pure-Rust SDK). |
| `src/modules/gcp/*` | Service-account-key issuance using `google-cloud-rust`. |
| `src/modules/azure/*` | App-registration / SP credential issuance. |

These cloud engines fit the framework cleanly because they all match the "create identity in external system, return creds, drop identity on revoke" pattern.

### Phase 4 -- SSH Dynamic-Keys Mode

Hook the `ssh` engine ([features/ssh-secret-engine.md](ssh-secret-engine.md)) into the framework so its third historical mode (push key to `authorized_keys` over outbound SSH, return private key, sweep on revoke) lands without bespoke lease handling.

### Phase 5 -- GUI Integration

| File | Purpose |
|---|---|
| `gui/src/routes/SecretsPage.tsx` (extension) | "Dynamic" tab listing dynamic mounts + roles. |
| `gui/src/components/DynamicCredsModal.tsx` | "Generate credential" button per role, returns the secret with a copy-to-clipboard + countdown timer to TTL. |
| `gui/src/routes/LeasesPage.tsx` | New page listing live leases with revoke + renew actions. |

### Not In Scope

- **OpenLDAP / AD password-rotation engines**. Vault has these but they're "static-secret rotation," not dynamic-secret generation. A separate feature.
- **Kubernetes service-account token engine**. Tracked separately under the (already-mentioned in roadmap) Kubernetes Integration initiative.
- **PKI lease-revocation hooks**. The PKI engine ([features/pki-secret-engine.md](pki-secret-engine.md)) issues certs without leases by design. If we ever add lease-tied PKI certs that auto-revoke on lease expiry, that's a Phase 5+ optional integration.
- **Wrap-response (`wrap_ttl`)**. The Vault response-wrapping pattern is broader than dynamic secrets; if we add it, it'll be a top-level feature, not part of this one.

## Testing Requirements

### Unit Tests

- Lease registration -> renew -> revoke -> tidy state machine. Mock backend that records calls.
- Connection pool: checkout, validate-fail, recycle; max-pool-size enforcement.
- Credential-cache: hit / miss / TTL-expiry / per-identity isolation.
- Audit emitter: every event field is HMAC-redacted by default unless explicitly whitelisted.
- Statement template engine: `{{name}}`, `{{password}}`, `{{expiration}}`, `{{role}}` substitution; SQL-injection-safe quoting (the engine produces parameterised statements where the driver supports them; otherwise it quotes per the dialect).

### Integration Tests

- **Postgres** (testcontainers + `tokio-postgres`): generate a role-based user, connect with the issued credential, run a query that the role's grants permit and one it doesn't (expect denial), revoke, attempt to reconnect (expect `role does not exist`).
- **MySQL** (testcontainers + `sqlx::mysql`): same shape.
- Lease renewal: generate at TTL=10s, renew at T+5s with new_ttl=20s, confirm credential still works at T+15s.
- Revoke-failed retry: simulate a target outage, mark the lease `revoke_failed`, bring the target back, confirm the reaper revokes within `2 * retry_interval`.
- Multi-engine lifecycle: register a `database` and an `aws` engine; lease lookup distinguishes them; revoke-all on a logout cascades correctly.

### Cucumber BDD Scenarios

- Operator configures a Postgres connection + a `readonly` role; an application requests a credential, uses it for 50 minutes, then the lease expires and the user disappears from Postgres.
- Operator runs `rotate-root` on the connection; in-flight leases continue to work (their grants persist), but new generation uses the new root credential.
- Operator force-revokes a lease via `/sys/leases/revoke`; the user is gone from Postgres within seconds and an audit event records the revoke.

### Negative Tests

- Generating a credential against a role whose connection's root credential has been revoked: clear error, no credential returned, no orphaned target user.
- Renew on a non-renewable lease: rejected.
- Renew past `max_ttl`: clamped to `max_ttl`.
- Concurrent revoke + renew on the same lease: one wins, the other gets a deterministic `LeaseAlreadyRevoked` / `LeaseAlreadyRenewed` error -- no orphaned target identity.

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`**: same constraint as PKI / Transit / TOTP / SSH. All target-system drivers must be configured to use `rustls` for TLS (`tokio-postgres = { features = ["with-rustls"] }`, `sqlx = { features = ["tls-rustls"] }`, etc.). CI must fail if `openssl-sys` or `aws-lc-sys` becomes reachable.
- **Root credential storage**: the per-connection root credential is the single most sensitive item this framework persists. It lives barrier-encrypted at `<engine>/config/<name>/root` and is *never* returned by `GET /v1/<engine>/config/<name>` -- only metadata is. `rotate-root` is the supported way to change it, and post-rotation the old credential is best-effort revoked in the target.
- **Statement templating**: SQL/IAM templates are operator-controlled, not user-controlled. The framework refuses to expand any token that isn't in a fixed allowlist (`{{name}}`, `{{password}}`, `{{expiration}}`, `{{role}}`, `{{display_name}}`, `{{entity_id}}`). Per-dialect quoting prevents the operator from accidentally writing an injection-vulnerable template against a user-supplied identity attribute.
- **Generated identity entropy**: usernames are derived from `v-<token-display>-<role>-<timestamp>-<8-hex>` (Vault-compatible). Passwords are 24 bytes from `OsRng`, rendered as URL-safe base64 (32 chars). Keys derived from cloud APIs use the cloud's own entropy.
- **Constant-time compare**: where the framework holds a credential to verify against (rare -- mostly cloud engines do this server-side), comparisons go through `subtle::ConstantTimeEq`.
- **Connection-pool isolation**: per-connection pools are keyed by `(connection_name, root_credential_version)`. After `rotate-root`, the old pool drains and is replaced -- no stale-credential connections survive a rotation.
- **Revoke-failed quarantine**: if `revoke()` fails, the lease enters `revoke_failed` state with the engine's last error captured. Operators can list these via `LIST /sys/leases/dynamic/revoke-failed` and force-clear after manual cleanup. The framework refuses to silently drop a lease whose target it could not clean up.
- **Audit completeness**: the framework guarantees every `generate` event has a paired `revoke` (or `revoke_failed`) event. A missing `revoke` event is itself an audit signal that something went wrong.
- **TLS verification**: every target connection verifies the server certificate against the system trust store (or an operator-supplied CA per connection) by default. `insecure_skip_tls_verify` exists for development only and is logged at WARN every time a connection uses it.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md), and this file's "Current State" / phase markers.
