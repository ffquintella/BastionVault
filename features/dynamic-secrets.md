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

**Status: in progress (T62).** Slices 1 to 6 are done, the GUI included.

| Slice | Scope | State |
|---|---|---|
| 1 | Host lease substrate: `revoke_failed` lease state with a backoff reaper, `v2/sys/leases/revoke-failed` list + force-clear, `sys/renew` for leases whose backend really renews them (max_ttl clamp, non-renewable refused), per-lease renew/revoke guard, `OwnedLeaseRevoker` early revoke by the issuing mount, `lease.*` audit events | Done |
| 2 | Plugin kind `secret/dynamic` (+ `engine_type`, ABI 1.5), the `dynamic_lease_register` / `dynamic_audit_emit` / `dynamic_pool_checkout` capabilities in both runtimes, the dynamic plugin host (generate / renew / revoke / rotate-root, host-side credential generation and statement templating) | Done |
| 3 | Connection pool and credential cache | Done: the bounded pool holds host-side connections (host connectors, PostgreSQL first) that a plugin uses through `dynamic_pool_checkout`'s additive `execute`, and still hands slot grants to plugins that dial; the opt-in credential cache is wired into `creds/`, entries per node, invalidation cluster-wide (see below) |
| 4 | `dynamic_secret` audit schema (engine / plugin / role / target identity) | Done |
| 5 | Dynamic SDK, Postgres reference plugin migration | Done in `dynamic-engine-plugins/`; removing the old copy from the `plugins-ext` submodule is left to its owner |
| 6 | GUI (Phase 5 below) | Done: Secrets → Dynamic, the credential dialog, the Leases page and the Plugins filter; the live-lease listing is limited to what the host serves (below) |

What slice 6 (the GUI) delivered, with no new server route:

- **Secrets → Dynamic** (`gui/src/components/DynamicSecretsSection.tsx`): the mounts whose plugin is in `GET /v2/sys/plugins?kind=secret/dynamic` (a plugin mount's type names only the plugin), each with its roles (`LIST <mount>/roles/`). Nothing loads until the tab is opened; a token that cannot read the catalog is told why no mount is shown.
- **Generate credential** (`gui/src/components/DynamicCredsModal.tsx`): reads `<mount>/creds/<role>` only on an explicit click, shows the credential once (masked, with copy) and a countdown to the lease's end, and drops it on close or expiry. It is never logged, cached or put in Web Storage; only the lease's id, mount, role and TTL go to an in-memory store (`gui/src/stores/leaseStore.ts`, cleared on logout). A cache hit (lease named in `data`) is flagged as a shared lease.
- **Leases** (`gui/src/routes/LeasesPage.tsx`, Admin → Leases): the `revoke_failed` listing with attempts, last error, next retry and TTL, retry revoke, and force-clear behind a typed confirmation; renew (renewable leases only) and revoke for the leases this window issued or any lease id. The host has **no listing of live leases** (`sys/leases/lookup` is not implemented), so no other live lease is shown.
- **Plugins → Dynamic engines**: the `?kind=` filter, `engine_type` and the three dynamic capabilities on a plugin's row; registration is unchanged (a bundle's `engine_type` and capabilities already pass through).
- **Tauri commands** (`gui/src-tauri/src/commands/leases.rs`, `dynamic_secrets.rs`, `plugins_list_by_kind`): lease calls are root-scoped (the lease paths refuse a namespace header). `sys/renew` and `sys/revoke` have no HTTP route, so remote mode sends them as one `POST /v2/sys/batch` operation; a batch drops the lease block, so a remote renew cannot report the new TTL and the page says so.

What slice 2 delivered (with the parts of slices 3 and 4 it needed):

- `crates/bv-dynamic` (new; `bv-kernel-api` + Tier 0 only) — the pure, separately tested pieces: the statement template engine (`template.rs`: exactly the six tokens, anything else refused, values restricted to quote-free character sets instead of dialect-specific escaping, `{{password}}` allowed only in creation statements), generated credentials (`credential.rs`: 24 bytes from the OS RNG as 32 URL-safe base64 characters, `v-<display>-<role>-<unix>-<8 hex>` usernames), the per-(mount, role, entity) credential cache (`cache.rs`), the keyed pool with drain-on-rotate and a TLS policy that verifies by default (`pool.rs`), the `dynamic_secret` event with no credential field (`audit.rs`), and the versioned records (`records.rs`: the lease's `bv_dynamic` blob, the host's connection record, the role recipe, the lease request).
- `crates/bv-plugin-manifest` — `plugin_type = "secret/dynamic"`, `engine_type` (one of `database`, `aws`, `gcp`, `azure`, `ssh`) and the three capabilities, ABI minor 5, capability minimisation both ways (a dynamic plugin may not declare the ABI 1.4 `sql_gate`, `resource_credentials` or `sql_console` either, since the dynamic host never runs it on a caller's behalf); none of the new fields enter an existing plugin's signing message or an ABI 1.4 grant pin. Minor 4 is the SQL browser substrate that shipped in 0.45.9 without this plugin kind; a 1.4 host ignores the dynamic keys, so a dynamic manifest declaring `1.4` is refused rather than loaded as an ordinary plugin.
- `src/plugins/dynamic/` — the host: `backend.rs` serves `creds/`, `config/`, `roles/`, `rotate-root/` and the lease manager's renew/revoke for a dynamic mount, reached from `PluginLogicalBackend` (`logical_backend.rs`), which still owns quarantine, the reload lock and the catalog lookup; `host_calls.rs` is the one capability gate both runtimes call (`runtime.rs` `bv.dynamic_*` imports, `process_runtime.rs` / `process_supervisor.rs` `dynamic_*` methods); `state.rs` keeps the host-owned per-mount records in the mount's own storage; `pool.rs` is the process-wide grant pool.
- `crates/bv-kernel/src/modules/auth/token_store.rs` — a secret marked `secret_type = "bv_dynamic"` (`expiration::HOST_MANAGED_SECRET_TYPE`) is leased on every mount, not only on `leased_passthrough` ones; the generic plugin bridge strips that marker from plugin answers.
- `src/plugins/quarantine.rs` — a quarantine record may carry a `reason`; an out-of-manifest dynamic host call writes one.
- `GET /v2/sys/plugins?kind=…` (`crates/bv-server/src/sys.rs`), additive and v2-only.

How it differs from the design below, and why:

- **The pool holds slots, and the host's own connections when it executes.** `dynamic_pool_checkout` returns a slot counted against the target's `max_size`, keyed by the root credential version and a config generation (a fresh random value on every `config/<name>` write, so a password-only change always drains), carrying the operator's TLS policy and, since the host connectors, `host_execute`: the connector kinds this host dials itself (`["postgres"]`), sent only for a connection whose endpoint the host has pinned (below). A plugin whose kind is listed sends the same call with `execute: {slot, connector}` (its stored connection: `kind`, `url`, `username`, `password`, optional `connect_timeout_secs`; no TLS field, no statements) and the host dials with `bv_dynamic::connector` under the operator's policy (verified TLS by default; plaintext only with `insecure_skip_tls_verify`; `sslmode=disable` refused otherwise; Unix-socket hosts refused), keeps the validated connection in the slot for reuse, and drains it on rotate-root, a config write or a TLS change, on every node (the record is re-read on each checkout). `deadpool` was not added: a keyed map with drain-on-rotate is a small bounded pool on `tokio::sync::Semaphore`.
- **The host runs only what it rendered.** An `execute` carries no statement: the host runs the plan it built for that call (`ExecPlan`: the role's rendered creation, renew or revocation statements, or the connector's own default renew/revoke for a role that has none; for rotate-root, the root-rotation plan below), once per call, on the connection the statements were rendered for, from a slot the call holds. Proxied calls (`config/`, `roles/`) have no plan, so their `execute` is refused. A revoke whose identity is already gone runs nothing (`identity_absent`). The root secret joins the call's redaction set: it reaches no log line, audit event or error. Additive within ABI 1.5 (no new import, method or capability): an older plugin ignores `host_execute` and dials; an older host has no `host_execute`, so a newer plugin dials; a plugin offered host execution must use it (no fallback dial after a host refusal).
- **Rotate-root runs on the target through the host too.** With the endpoint pinned, a `rotate-root/<connection>` call carries a plan: the root user is the pinned `username`, the new secret is the host's (generated as before), and the statements are the connection's `root_rotation_statements` (host-owned on `config/<name>` like the TLS policy: `{{name}}` and `{{password}}` only, rendered by the template engine) or the connector's default (PostgreSQL: `ALTER ROLE "<root>" WITH PASSWORD '<new>'`, identifier and literal quoted, built without intermediate copies). On the plugin's `execute` the host renders both the rotation and its undo (the same statements with the current secret) before touching anything, so a current secret that could not be put back refuses the rotation up front; proves the presented current secret with a fresh login (never a pooled connection: it is the undo value); sets the new secret over that connection and proves it with another fresh login; on a failed login puts the old one back and proves the old one logs in again. The host's rotation budget is 18 s, inside the 30 s a plugin call gets; an in-flight record set before the target is touched catches a call the runtime cuts short anyway. The plugin then only stores the new secret. The host undoes its change only when the plugin ran to the end and said it did not store it (`root_stored: false`, the SDK's `RootNotStored`): then it puts the old secret back over a login with the new one, checks the old one logs in, and answers `502` "was undone … nothing changed". Any other ending after the host's change (a timeout, a crash, a quarantine, a failure that does not say, success after a host rollback, a cut-short host call, a failed undo) is **stranded**: an explicit `502` naming the connection and saying a new root secret may be on the target and not stored, logged at ERROR and audited as a failed `rotate_root`. On success the connection's pool slots are drained (new root credential version) and the cache epoch is bumped, as before. A plugin not offered host execution (unpinned endpoint, older host) still sets and stores the secret itself.
- **One rotation per connection, and a stranded one is never forgotten.** A rotate-root first writes a marker on the host's connection record (start time, node, a nonce; no secret) under the record lock: an in-process mutex plus the storage backend's `lock()`, which is cluster-wide on hiqlite (the client's distributed lock) and MySQL, process-local on the file backend and absent on the cloud file targets (no backend offers compare-and-set, so on those a cross-node race is not excluded). A second rotate-root while it stands is a `409` ("in progress"; after 120 s "never finished … may hold a new root secret"; after a stranded one, "reset it by hand"). The marker is cleared only by its own rotation (re-reading the record and merging just the version bump, so a `config/<name>` write meanwhile is kept) or by an operator's `DELETE rotate-root/<connection>` (audited), never by age. A `config/<name>` read shows it (and warns when possibly stranded); deleting the connection is refused while it stands. Every other read-modify-write of the record (config writes and deletes) takes the same lock.
- **The host dials only the endpoint the operator configured.** On every accepted `config/<name>` write the host records the non-secret `connection_url` and `username` in its own connection record; an `execute` presenting anything else is refused, so a plugin (a WASM one included) cannot make the vault dial an arbitrary host:port or use it as a port-scan oracle. A connection without both pinned (a record written before this change, a plugin whose schema names them differently, or a write that cleared one) gets no `host_execute`: the plugin dials itself as before, and an operator re-writes `config/<name>` to opt in. Each dial is logged at INFO with its `host:port`, user and TLS mode, never a secret. The root secret still comes from the plugin's stored connection (presented on each `execute`); the host keeps no copy of it, and with the endpoint pinned a wrong secret can only fail authentication there.
- **What host execution does not change.** A process plugin is still not network-sandboxed and the slot-grant path remains for plugins that dial, so the TLS policy is enforced by the host only on the connections the host opens. aws-lc-sys was already in the host graph (bv-errors' rustls); the connector uses the `ring` provider explicitly and adds no openssl-sys or aws-lc-sys path.
- **Roles are the plugin's, templates are the host's.** The host asks the plugin for a role's recipe (`dynamic.role`), checks and expands its statements, generates the credential, then hands the rendered statements to the plugin (`dynamic.generate`). Revocation statements are expanded at generation and kept on the lease; renew statements are kept as templates.
- **The generate event has no lease id.** The lease id is assigned when the kernel registers the lease, after the plugin host has answered; the `generate` event carries the request id and the target identity instead, and `renew` / `revoke` / `revoke_failed` events join on the target identity (revoke ones carry the lease id).
- **A cache hit names its lease in `data`.** A hit answers without a `secret`, so the kernel registers no second lease; the shared lease is in `data.lease_id` / `lease_duration` / `renewable`. The miss learns its lease id from the kernel through a slot it leaves in the request context (`expiration::HOST_MANAGED_LEASE_SLOT`), since the backend answers before the lease exists.
- **"Unloaded" means not resident.** Every RPC resolves the active plugin from the catalog and the runtimes instantiate (WASM, single-shot process) or respawn (long-lived process) it, so revoking a lease never needs the plugin loaded; a deleted (quarantined) plugin makes the revoke fail and keeps the lease `revoke_failed` until the plugin is registered again.

Host-call protocol of `dynamic_pool_checkout`: `{"connection"}` → `{"connection","root_credential_version","tls","slot","max_connections","host_execute":[kinds]}`; `{"connection","execute":{"slot","connector":{"kind","url","username","password"[,"connect_timeout_secs"]}}}` → `{"executed": n, "identity_absent": bool}` (a root rotation adds `"rotated": true`), or `invalid: …` (malformed, another connection, unknown kind, slot not held, no plan or already ran) / `unavailable: …` (dial or statement failure, redacted).

Plugin protocol (both runtimes, JSON envelopes): `{"op":"dynamic.role","role"}` → `{"data": <recipe>|null}`; `{"op":"dynamic.generate","role","connection","statements","credential":{"username","password","expiration"},"ttl_secs"}` → the plugin creates the identity, calls `dynamic_lease_register` with `{"internal","ttl_secs","max_ttl_secs","renewable"}` exactly once, and answers `{"data":{…extra fields}}`; `{"op":"dynamic.renew"|"dynamic.revoke","role","connection","username","statements","internal",…}`; `{"op":"dynamic.rotate_root","connection","credential":{"password"}}` (the new root secret, generated by the host); and the generic `{op, path, data}` envelope for `config/` and `roles/`. Process host replies are matched by `id` and carry `result` or `error`; the server tags an error reply `host_reply_error` (the testkit `host_reply`), so a plugin reads both.

What the T62 fix pass changed (security review and slice-3 follow-ups):

- **A credential is never left behind by a failed registration.** `creds/` checks the namespace's `max_leases` before the plugin is called (`OwnedLeaseRevoker::check_lease_quota`, reached through `VaultCtx::lease_revoker()`); and when the kernel still cannot register a host-managed lease (quota filled meanwhile, storage error), `ExpirationManager::register_host_managed_secret` revokes the credential through the plugin at once, or keeps it as `revoke_failed` (origin `registration`) when that revoke fails.
- **A quarantined generate is reported.** A plugin quarantined half-way through `generate` is not called again; the identity it may have created is logged at ERROR and audited as `revoke_failed` with role, connection and target identity.
- **Compensation errors are redacted.** The take-back revoke's session carries the password as a redaction needle, so a plugin error echoing it reaches neither the ERROR log nor the audit event; the kernel's take-back passes the issued data along for the same reason.
- **Lease rows no longer store the password.** A host-managed lease row keeps `data` without `password` (read-old/write-new: an older row loses it on its next write).
- **Plugin storage is per mount.** A dynamic plugin's `storage_*` root is `core/plugins/<name>/data/mounts/<mount id>/` in both runtimes, and it has no storage outside a dynamic RPC. Slice-2 data under the per-name root is not migrated (slice 2 is unreleased).
- **Host-call order matches the testkit.** The session is checked in `authorize`, before the request is parsed; the testkit exports `DYNAMIC_UNAVAILABLE`.
- **The credential cache is wired** (see *Credential-Cache Layer*): `cache_ttl_secs` on the role (SDK: `cache_ttl`), clamped to 300 s and to end while the lease has `max(2 x window, 60 s)` left; dropped on any revoke or renew of its lease, rotate-root, role rewrite, plugin delete/activate/quarantine and expiry, on every node; bounded to 4096 entries per node, oldest first; a hit is a `cache_hit` event without the credential.

What slice 5 delivered, in the separate Cargo workspace `dynamic-engine-plugins/` (excluded from the host workspace; `make dynamic-plugins-test`):

- `bastion-plugin-dynamic-sdk` — re-exports `bastion-plugin-sdk`; the `DynamicCredentialBackend` trait (`generate` / `renew` / `revoke` / optional `rotate_root`, plus the connection schema and role/connection validation hooks); `DynamicCtx` (pool checkout, plugin audit events, `state/` storage, redaction; no way to register a lease); the dispatcher, which serves `dynamic.role` from `roles/<name>` (refused when the connection's `allowed_roles` does not admit it, before the host generates anything), the CRUD of `config/` (secret fields stored, never read back) and `roles/`, and registers the lease **once, after** a successful `generate`; the process loop (single-shot and long-lived, constant-time bootstrap-token check) and the WASM glue (`bv.dynamic_*` imports, `dynamic_module!`, no retry of a call whose reply did not fit, since the host already acted); `testing::MockHost`. Credentials arrive rendered and are `SecretString`s (no `Display`/`Serialize`, redacted `Debug`, wiped on drop); error text is redacted before it leaves; a reply, lease blob or audit label carrying a known secret is refused; diagnostics name only the op and an error kind.
- Host execution in the SDK and the plugin: `PoolGrant::host_execute` / `executes(kind)`, `DynamicCtx::host_execute(grant, HostConnector)` (the root secret is remembered for redaction and the request is wiped after framing), `MockHost::executing(kind)`; the testkit's `TestHostBuilder::dynamic_host_execute(kind)` and `TestInvocation::dynamic_executions` model the server's refusals. `bastion-plugin-postgres` has the host run generate, renew, revoke and the target side of rotate-root when the grant lists `postgres` (never dialling around a refusal; on rotate-root it only stores the new secret, and a store failure fails the call so the host undoes it), and dials otherwise.
- `bastion-plugin-postgres` 0.2.0 — the reference plugin rebased on the SDK, `runtime = "process"`, capabilities exactly the three dynamic ones plus `storage_prefix = ""`. `tokio-postgres` over rustls on the `ring` provider (no `openssl-sys`, no `aws-lc-sys`, checked by the make target): verifies against the connection's CA or the OS trust store and requires TLS (`sslmode=disable` refused) unless the host's grant carries the operator's `insecure_skip_tls_verify`. Creation statements run in one transaction; revoke is `DROP OWNED BY` + `DROP ROLE IF EXISTS` by default and succeeds for a role already gone; renew is `ALTER ROLE … VALID UNTIL` by default; `rotate-root` sets the host's new secret, stores it, and restores the old one if storing fails. `connection_url` may not carry a user or password.
- `bastion-plugin-dynamic-fixture` — a fake engine that runs the SDK through `bastion-plugin-testkit` as a real process and as WASM, i.e. against the host's wire protocol and capability gate.

The host connector's own live test (`crates/bv-dynamic/tests/postgres_live.rs`, `cargo nextest run -p bv-dynamic --test postgres_live --run-ignored only`; same container helper, `BV_TEST_REQUIRE_CONTAINER=1` turns a missing engine into a failure) creates, renews and revokes against `postgres:16`, checks pooled reuse, drain on rotate and that the verifying default refuses the plaintext server, and rotates the root (the old secret stops logging in, the new one does, a credential made before and one made after both work, and the undo brings the old secret back); it is `#[ignore]` and not in CI either. Not exercised against a real server: the failed-login rollback and a failing undo (fake connector only).

Not yet: a host-side end-to-end test with the real Postgres binary (the main workspace does not build plugin binaries; the testkit runs stand in for it); the live-database test (`tests/live.rs`, `make dynamic-plugins-live`) starts its own docker or podman container and is `#[ignore]`, so no CI job runs it yet; the old `plugins-ext/bastion-plugin-postgres` was removed from the submodule.

What slice 1 delivered, and where it lives (older paths elsewhere in this spec are stale; corrections follow the list):

- `crates/bv-kernel/src/modules/auth/expiration.rs` — the lease manager. A secret lease whose backend revoke fails is **kept** with a `revoke_failure` record (attempts, first/last failure, next attempt, last error cut to 256 characters, origin) instead of being deleted; the sweeper doubles as the reaper (10 s, doubling, `max_revoke_attempts` = 6, then parked and listed). Lease rows carry `version` 1 and `max_ttl_secs`; version-0 rows read unchanged. Not yet operator-configurable: `max_revoke_attempts` is the spec default.
- `crates/bv-kernel/src/modules/auth/lease_state.rs` — the retry policy, the per-lease guard (a renew and a revoke of one lease never overlap; the loser gets a `409`) and the `lease.revoke_failed` / `lease.revoked` / `lease.revoke_failed_cleared` events, emitted through the kernel's audit-event path (`bv_kernel_api::mcp_events::emit`, broker `event` entries).
- `crates/bv-kernel/src/modules/system/leases.rs` — `sys/renew` (now renews), `sys/revoke` (`502` + kept on backend failure), `sys/leases/revoke-failed` (`LIST`) and `sys/leases/revoke-failed/<lease_id>` (`DELETE`, force-clear), HTTP-routed under `/v2/sys` only by `crates/bv-server/src/sys/routes.rs`. See `docs/api.md` § Leases.
- `crates/bv-kernel-api/src/leases.rs` — `OwnedLeaseRevoker`, reached as `VaultCtx::lease_revoker()`: a mount revokes a lease it issued (path must route to exactly that mount; token leases refused). No engine calls it yet.

Corrections to the paths below: there is no `src/modules/dynamic/` or `src/sys/leases.rs`; the lease manager and lease endpoints are the `crates/bv-kernel/…` files above, KV v1's lease is `crates/bv-engine-kv/src/v1.rs`, and the plugin runtime is `src/plugins/…`. A plugin mount's type is `plugin:<name>` (`src/plugins/mod.rs`, `PLUGIN_MOUNT_PREFIX`), and the manifest's kind is the free-form `plugin_type` string (`crates/bv-plugin-manifest`), so "plugin kind `secret/dynamic`" means a new `plugin_type` value, not a parser change.

- **Lease manager**: slice 1 gave it the revoke-failed state, renewal and early revoke; slice 2 added the abstraction for "the secret lives in an external system the host must call out to on revoke" — the dynamic plugin host, whose leases are registered on every mount.
- **Connection pool**: the host pool admits connections per target (max size, root-credential version, config generation, TLS policy) through `dynamic_pool_checkout`, and holds the host's own validated connections for plugins that have it execute (`bv_dynamic::connector`, PostgreSQL first; see above).
- **Credential cache**: `bv-dynamic::cache` behind `creds/` (`src/plugins/dynamic/cache.rs`), opt-in per role, keyed by mount, role and caller entity, never for a caller without one; invalidated cluster-wide through records in the mount's storage.
- **Credential-lifecycle audit**: every `generate`, `renew`, `revoke`, `revoke_failed` and `rotate_root` is a `dynamic_secret` event (engine, `plugin@version`, role, connection, target identity, expiry, actor), so a SOC can answer "what credentials were live in this DB at 14:32 last Tuesday?" from the audit log.
- The repo's existing engines (`kv`, `kv_v2`, `crypto`, `files`, `resource`, `system`) are all **static** — they store data, they don't mint it. Dynamic secrets is the first engine class where the interesting state lives outside BastionVault.
- **The plugin system** (publisher signatures, manifest verification, quarantine, hot-reload lock, metrics, process supervisor) now also exposes the three dynamic-secret host capabilities, at ABI minor 5, through the same gate in both runtimes (and on the ABI 1.4 multiplexed child of a `concurrent` long-lived plugin, which carries the dynamic session per invocation); the guest-side SDK for them (`bastion-plugin-dynamic-sdk`, slice 5) is in `dynamic-engine-plugins/`.

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

### Reuse of the existing plugin engine

**This feature MUST NOT introduce a second plugin runtime.** Dynamic-secret engines run on the same plugin engine that already ships ([features/plugin-system.md](plugin-system.md), Phases 1–5). Concretely, every component listed below is reused as-is — this feature only *extends* the plugin engine with a small set of dynamic-shaped host capabilities and one new plugin `kind`. Building a separate dynamic-only loader, manifest format, signing chain, supervisor, or sandbox would duplicate code, double the operator's mental model, and split the trust surface in two.

| Existing plugin-engine component | What dynamic-secret engines reuse it for |
|---|---|
| [`src/plugins/runtime.rs`](../src/plugins/runtime.rs) — WASM runtime (`wasmtime`) | Loads `runtime = "wasm"` dynamic plugins (lighter footprint; suitable for engines whose target driver compiles to `wasm32-wasip1`). |
| [`src/plugins/process_runtime.rs`](../src/plugins/process_runtime.rs) — out-of-process runtime (line-delimited JSON-RPC) | Loads `runtime = "process"` dynamic plugins (most database / cloud engines; their drivers don't compile to WASM today). |
| [`src/plugins/process_supervisor.rs`](../src/plugins/process_supervisor.rs) — process supervisor | Owns the lifecycle of every process-runtime dynamic plugin: spawn, health-check, crash-restart, graceful shutdown. A plugin crash never takes down the host. |
| [`src/plugins/manifest.rs`](../src/plugins/manifest.rs) — manifest schema + parser | Parses the `[plugin]` and `[capabilities]` sections of every dynamic plugin's manifest. Dynamic plugins use `kind = "secret/dynamic"` (a new value); everything else in the manifest schema is unchanged. |
| [`src/plugins/verifier.rs`](../src/plugins/verifier.rs) — publisher signature verification | Same gate, same keys, same operator opt-in for `unsigned` development. A dynamic-secret plugin without a signed manifest is refused load by the existing code path. |
| [`src/plugins/catalog.rs`](../src/plugins/catalog.rs) — plugin catalog (`/v1/sys/plugins/catalog/...`) | The same catalog endpoints register / list / remove dynamic plugins. Filtering by kind (`?kind=secret/dynamic`) is a small additive surface; everything else is unchanged. |
| [`src/plugins/quarantine.rs`](../src/plugins/quarantine.rs) — quarantine on misbehaviour | A dynamic plugin that exceeds capability budget, panics repeatedly, or fails health checks is quarantined by the existing logic — no engine-specific quarantine. |
| [`src/plugins/reload_lock.rs`](../src/plugins/reload_lock.rs) — hot-reload lock | Used unmodified to safely swap a dynamic plugin's binary while leases are live: the lock blocks new `generate` calls during the swap; in-flight `renew`/`revoke` complete against the old instance, then traffic resumes against the new one. |
| [`src/plugins/metrics.rs`](../src/plugins/metrics.rs) — plugin metrics | Dynamic plugins inherit the per-plugin call-count / error-rate / latency metrics for free. The framework adds engine-shaped metrics (lease lifetime, pool wait time) on top — those live in `src/modules/dynamic/`. |
| [`src/plugins/module_cache.rs`](../src/plugins/module_cache.rs) — compiled-WASM module cache | Reused as-is for WASM dynamic plugins. |
| [`src/plugins/logical_backend.rs`](../src/plugins/logical_backend.rs) — generic logical-backend bridge | The dynamic-secret plugin host (`src/modules/dynamic/plugin_host.rs`) is a *thin specialisation* of this bridge, not a parallel implementation. Where `logical_backend.rs` routes generic CRUD to a plugin, `plugin_host.rs` routes the dynamic-shaped RPC verbs (`generate`, `renew`, `revoke`, `rotate_root`) to the same plugin process / module. |

What this feature **adds** to the plugin engine is exactly:

1. **One new plugin kind**: `secret/dynamic`. Recognised by the existing manifest parser; routed to the dynamic-secret host instead of the generic logical-backend bridge.
2. **Three new host capabilities** surfaced through the existing capability-gating layer:
   - `dynamic_lease_register` — the plugin asks the host to register a generated credential as a lease.
   - `dynamic_audit_emit` — the plugin emits a structured `dynamic_secret` audit event.
   - `dynamic_pool_checkout` — the plugin checks out a pooled connection from the host's connection pool.

   These follow the **existing capability ABI** (typed request, typed response, capability name in the manifest, refusal for out-of-manifest calls). No new gating logic, no new permission model.
3. **One new SDK crate**, `bastion-plugin-dynamic-sdk`, that depends on the existing `bastion-plugin-sdk` and re-exports its primitives. Plugin authors continue to use the same SDK conventions they already know from `plugins-ext/`.

Out-of-tree plugin authors writing a dynamic engine **should not need to learn anything new about the plugin engine itself** — manifest schema, signing flow, runtime selection, capability declaration, supervisor behaviour, and the catalog API are identical to what they've already used. The only delta is the SDK trait they implement (`DynamicCredentialBackend` instead of the generic logical-backend trait) and the three additional capabilities they declare.

### Plugin host integration

The framework registers a new plugin **kind** with the existing plugin engine: `secret/dynamic`. The manifest schema, signing requirement, runtime choice, capability declaration, and catalog endpoints are all the existing plugin-engine surface (see the table above) — only the `kind` value and the three dynamic-shaped capabilities are new. A manifest looks like:

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

When an operator does `bvault secrets enable --path=postgres-prod database` (BastionVault uses clap-style `--path`, not Vault's single-dash `-path`), the framework:

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

**Cluster-wide invalidation (as built).** Entries live in each node's memory, but whether one may be served is decided on every hit by two records in the mount's own (replicated, barrier-encrypted) storage, so no new transport is needed:

- the credential's **marker** (`bv-dynamic/cache/credentials/<username>`: a random nonce and an expiry, no credential), written before the entry is cached and deleted by whichever node renews or revokes its lease, before the plugin is called. The lease row records `cached: true` (additive field), so only cached leases pay the delete.
- the mount's **epoch** (`bv-dynamic/cache/epoch`: a random nonce), rewritten after every attempted role write or delete, config write or delete, and rotate-root (also when the plugin reports failure, since it may have changed its stored record anyway). A miss reads it *before* reading the role, so a role write that lands meanwhile refuses the new entry too. Nonces are written blind (never read-modify-write), so concurrent writers on two nodes cannot lose an update.
- the plugin's **build** (`name@version#sha256`), compared with the active catalog record: another active build makes the entry a miss. A quarantined or deleted plugin's mount is refused before the cache on every node.

Cost: two storage reads per hit, one per miss (the epoch), one write per cached miss, one delete per renew or revoke of a cached lease, one write per role or config write and rotate-root. **Failure mode: fail closed.** An unreadable epoch or marker (storage error, or a record format this node does not know) is a miss and drops the entry; a marker or epoch that cannot be written means the credential is not cached. A marker that cannot be deleted fails the renew (an error) or the revoke (the lease is kept `revoke_failed` and retried); a role write or rotate-root whose epoch cannot be advanced answers `503` saying the change was applied and that other nodes may serve credentials cached before it for up to 300 s. Reads are as consistent as the storage backend's (hiqlite: a node may read its replica up to its replication lag). **Rolling upgrades:** a node still on a version without these records (0.45.10 and older) neither deletes a marker when it renews or revokes a cached lease nor bumps the epoch on a role write or rotate-root, so while such a node handles those operations an upgraded node may serve a credential it cached for the rest of its window (at most 300 s). Keep `cache_ttl_secs` at 0 until every node runs a version with cluster-wide invalidation. Entries never outlive the lease's own expiry, since an entry ends while its lease still has `max(2 x window, 60 s)` to run.

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
| Plugin host capability set        | New `dynamic_lease_register`, `dynamic_audit_emit`, `dynamic_pool_checkout` capabilities surfaced through the existing plugin runtimes ([src/plugins/runtime.rs](../src/plugins/runtime.rs) for WASM, [src/plugins/process_runtime.rs](../src/plugins/process_runtime.rs) for process). New plugin kind `secret/dynamic` recognised by the existing manifest parser ([src/plugins/manifest.rs](../src/plugins/manifest.rs)). **No new runtime, supervisor, sandbox, signing chain, catalog, or quarantine logic** — the framework reuses every component listed in the "Reuse of the existing plugin engine" section above. |
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

### Phase 5 — GUI Integration (Complete, T62 slice 6)

The Leases page lists live leases only as far as the host can: see *What slice 6 (the GUI) delivered* above.

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
- **Connection-pool isolation**: per-connection pools are keyed by `(connection_name, root_credential_version)` and live in the host. After `rotate-root`, the old pool drains and is replaced — no stale-credential connections survive a rotation. Plugins cannot bypass the pool to open a raw socket with cached root creds. *As built:* keyed by `(mount, connection, root_credential_version, config_generation)` and drained on any change of those or of the TLS policy; a process plugin can still dial itself (the slot-grant path), so "cannot bypass" holds for WASM plugins and for the connections the host opens.
- **Revoke-failed quarantine**: if the plugin's `revoke()` fails, the lease enters `revoke_failed` state with the plugin's last error captured. Operators can list these via `LIST /sys/leases/dynamic/revoke-failed` and force-clear after manual cleanup. The framework refuses to silently drop a lease whose target it could not clean up.
- **Audit completeness**: the framework guarantees every `generate` event has a paired `revoke` (or `revoke_failed`) event. A missing `revoke` event is itself an audit signal that something went wrong.
- **TLS verification**: every target connection verifies the server certificate against the system trust store (or an operator-supplied CA per connection) by default. `insecure_skip_tls_verify` exists for development only and is logged at WARN every time a connection uses it. The pool is the chokepoint that enforces this — a plugin cannot turn off verification on its own.
- **Plugin process isolation**: process-runtime plugins run as separate OS processes under the existing supervisor ([src/plugins/process_supervisor.rs](../src/plugins/process_supervisor.rs)). A plugin crash does not take down the host. WASM-runtime plugins are sandboxed by `wasmtime` capability gating.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [ROADMAP.md](../ROADMAP.md), and this file's "Current State" / phase markers. Plugin releases under `dynamic-engine-plugins/` track their own versions; the host CHANGELOG records "framework supports plugin X starting at version Y," not the per-plugin release notes.
