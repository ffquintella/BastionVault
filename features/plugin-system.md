# Feature: Plugin System (Dynamic Loading)

## Summary

Add a **plugin system** that lets BastionVault load secret engines, auth backends, audit devices, and database drivers from external artefacts at runtime, without rebuilding the BastionVault binary. Two execution backends are shipped, chosen per-plugin:

1. **WASM (default, sandboxed, in-process)** — plugins are `.wasm` modules executed in `wasmtime` with a strict capability set (storage view, audit emitter, KMS-style crypto host calls). This is the recommended path for new plugins and the only option for untrusted authors.
2. **Out-of-process gRPC (for plugins that need real networking or system access)** — plugins are separate executables that BastionVault launches and talks to over a Unix-domain socket or Windows named pipe via `tonic`/`prost`. Used when a plugin needs to open arbitrary outbound TCP (cloud SDKs, DB drivers) or access the filesystem outside the WASI sandbox.

Both backends share **one** plugin protocol — a versioned `PluginService` defined in `.proto` files — so the same conceptual plugin can be packaged either way. Native cdylib loading (`libloading` / `dlopen`) is **explicitly rejected**: the Rust ABI is unstable, version skew between host and plugin is silent and catastrophic, and the security boundary is non-existent.

The plugin system is a substrate, not an engine. Concrete out-of-tree plugins (e.g. an Oracle database driver, a Vault PKCS#11 bridge, a vendor-specific HSM seal) consume it as a SDK without touching `bastion-vault` source.

## Motivation

- **The "Todo" rows on the roadmap are an open list, not a closed one**. Customers will keep asking for engines we haven't built — Oracle, Snowflake, vendor-specific HSMs, internal-only auth providers — and shipping every one as a first-party module is unsustainable. A plugin system shifts that work to the customer (or to a partner) without forking the codebase.
- **Vault parity is part of the migration story**. HashiCorp Vault has had `vault plugin register` since 0.8; large customers have fleets of internal plugins. Reimplementing the surface (with a saner protocol) is required to be a credible drop-in target.
- **WASM-first is a security upgrade over Vault**. Vault's plugin model relies on subprocess isolation + a shared mutual-TLS key; a compromised plugin can do anything the OS user can. WASM gives us capability-based isolation by default — a misbehaving plugin can only touch the storage paths and audit channels we hand it explicit references to. That's the right default for a secrets manager.
- **Keeps the core small**. Every cdylib / built-in engine is a build-time dependency that bloats the binary, increases supply-chain surface, and forces every customer to pay the cost of every other customer's wishes. Plugins flip that equation: customers compile only the plugins they actually use into their deployment.
- **Decouples release cadence**. Today a fix to a database driver requires a BastionVault release. With plugins, a partner ships a new `.wasm` and customers pick it up on their own schedule.

## Current State

**Phase 1 substrate is shipped; Phases 2–4 are partial.** Concretely:

### Shipped

- **WASM runtime** ([src/plugins/runtime.rs](../src/plugins/runtime.rs)) — `wasmtime`-backed, fuel + memory caps per-invocation, no fs / no net / no env / no clocks beyond monotonic. Module-cache layer ([src/plugins/module_cache.rs](../src/plugins/module_cache.rs)) keeps compiled `wasmtime::Module` instances for repeat invokes; invalidated on activate/reload.
- **Capability-gated host imports** — `bv.log`, `bv.set_response`, `bv.now_unix_ms`, `bv.config_get`, `bv.storage_{get,put,delete,list}` (gated on `manifest.capabilities.storage_prefix`), `bv.audit_emit` (gated on `audit_emit`). Storage view is rooted at the plugin's per-mount UUID prefix; out-of-prefix reads are refused before touching the barrier.
- **Catalog + manifest** ([src/plugins/catalog.rs](../src/plugins/catalog.rs), [src/plugins/manifest.rs](../src/plugins/manifest.rs)) — sha256 integrity enforced on write *and* on every load; per-name version history + `set_active` + `delete_version`; manifest declares capability footprint and operator-supplied config schema (`ConfigField` / `ConfigFieldKind`).
- **Operator-supplied config** ([src/plugins/config.rs](../src/plugins/config.rs)) — `PUT /v1/sys/plugins/<name>/config` populates a barrier-stored map that the plugin reads via `bv.config_get`.
- **HTTP surface** ([src/http/sys.rs](../src/http/sys.rs)) — `POST/GET/DELETE /v1/sys/plugins`, version list/activate/delete, `POST /v1/sys/plugins/<name>/reload`, invoke endpoint.
- **LogicalBackend mount wiring** ([src/plugins/logical_backend.rs](../src/plugins/logical_backend.rs)) — `mount type=plugin:<name>` dispatches to the runtime; the same `Request`/`Response` shape the built-in engines use flows through.
- **`bastion-plugin-sdk` crate** ([crates/bastion-plugin-sdk](../crates/bastion-plugin-sdk)) — `Plugin` trait, `Host` capability handle, `register!` macro emits the WASM ABI exports (`bv_run` + `bv_alloc` + linear `memory`).
- **`bv-plugin-pack` packer CLI** ([crates/bv-plugin-pack](../crates/bv-plugin-pack)) — bundles `plugin.toml` + `.wasm` into a `.bvplugin` artefact the GUI can self-configure on upload.
- **Reference plugins out-of-tree** ([plugins-ext/](../plugins-ext/) git submodule) — `bastion-plugin-totp` (full WASM port of the TOTP engine) and `bastion-plugin-postgres` (process-runtime dynamic-secrets PoC).
- **GUI** ([gui/src/routes/PluginsPage.tsx](../gui/src/routes/PluginsPage.tsx)) — register modal with manifest preview, list/delete/invoke, version activation, error surfacing.
- **Process runtime as single-shot spawn-per-invoke** ([src/plugins/process_runtime.rs](../src/plugins/process_runtime.rs)) — host writes the binary to a temp file, spawns it, exchanges request/response over stdin/stdout, kills on timeout. Useful for "I need real network access *for one call*" cases; **not** the long-lived supervised gRPC subprocess the spec calls for.

### Outstanding gaps (in priority order)

1. **`bv.crypto_*` host capability — biggest functional gap.** Plugins cannot sign / encrypt / decrypt under a Transit key without seeing the bytes. `manifest.capabilities.allowed_keys` is declared but unenforced. Now unblocked by the Transit engine landing (Phases 1–4); concrete wiring is `bv.crypto_encrypt(key_handle, plaintext) → ciphertext`, `bv.crypto_sign(key_handle, message) → sig`, `bv.crypto_decrypt`, `bv.crypto_verify`, `bv.crypto_random(n)`. Allow-list is the manifest's `allowed_keys` matched against the operator-mounted Transit path.
2. **ML-DSA-65 publisher signature verification.** Catalog enforces sha256 only. Spec calls for plugins signed by a publisher key (a Transit ML-DSA-65 key role), an operator-configured publisher allowlist, and `accept_unsigned = true` development opt-in (logged at WARN). Now unblocked by Transit shipping ML-DSA-65.
3. **Long-lived supervised process runtime.** Replace the current spawn-per-invoke with: subprocess launched with a single-use 60 s bootstrap token over a UDS / Windows named pipe, `tonic`/`prost` `PluginService` RPCs over the socket, health checks, restart-with-exponential-backoff, log-line forwarding tagged with `plugin=<name>`, optional Linux `process_user` for per-plugin OS-level uid drop.
4. **Versioned `PluginService` `.proto` shared across runtimes.** Today WASM uses a custom byte-shovel ABI and process uses raw stdin/stdout; the spec's central design point — that both runtimes share one wire schema with a major.minor version check — is not yet expressed as a `.proto` + `tonic-build`. Adding it makes the WASM ABI and process gRPC literally the same codegen output.
5. **Net allowlist enforcement** — `allowed_hosts` declared in the manifest but no `host/net.rs` gate. Process plugins inherit unconstrained OS network access today. The wildcard-host rejection (`allowed_hosts = ["*"]` refused at registration) also needs to be added.
6. **Hot-reload drain-and-swap.** `POST /v1/sys/plugins/<name>/reload` exists but only invalidates the module cache. Spec wants: write-lock the mount instances, drain in-flight (configurable, default 10s), queue-during-swap, return `plugin_reloading` after queue timeout, audit the swap with `(old_version, new_version, in_flight_count, actor_entity_id)`.
7. **Quarantined-mount state on plugin delete.** Deleting a plugin today removes the catalog record; mounts that pointed at it now fail. Spec wants the storage prefix preserved + a `quarantined` mount state so an accidental delete is reversible by re-registering the same plugin.
8. **Lease / renew / revoke plumbing.** LogicalBackend dispatches `Read`/`Write`/`Delete`/`List` to the plugin; the `operation="renew"` / `"revoke"` cases that let a plugin-issued lease drive its own lifecycle through the existing lease manager are missing. Required for any dynamic-secrets plugin (the Postgres reference plugin works around this today by being out-of-process and managing its own state).
9. **Capability-widening guard.** Re-registering a plugin with broader capabilities should require the full signature ceremony, not just an `accept_unsigned` re-upload. Today it appears to silently accept the new manifest.
10. **`PluginService` ABI version check** — the `manifest.abi_version` field is parsed but not compared against a host-side compatible-major set; mismatches silently pass.
11. **Per-plugin metrics on the GUI** — Phase 3 deliverable; today the GUI shows catalog state but no per-plugin invoke counts / latency / fuel-consumed.
12. **End-to-end integration tests for the reference plugins inside the main test suite** — the `plugins-ext/*` submodule plugins exist but are not exercised from `bastion_vault`'s integration tests.

The core substrate is solid enough for early adopters writing internal plugins; the four gaps that block "production-grade" use are #1 (no crypto host), #2 (no signature verification), #3 (no real process supervisor), and #6 (reload is too coarse for live operations).

## Design

### Plugin Protocol (`PluginService`)

A single `.proto` schema, versioned, generated for both Rust (host + out-of-process plugin) and consumed by the WASM bindings:

```proto
service PluginService {
  rpc Initialize(InitializeRequest) returns (InitializeResponse);
  rpc Setup(SetupRequest) returns (SetupResponse);
  rpc HandleRequest(PluginRequest) returns (PluginResponse);
  rpc Cleanup(CleanupRequest) returns (CleanupResponse);
  rpc HealthCheck(HealthRequest) returns (HealthResponse);
}

message PluginRequest {
  string operation = 1;     // "read" | "write" | "delete" | "list" | "renew" | "revoke"
  string path = 2;
  map<string, bytes> data = 3;
  RequestContext ctx = 4;   // identity, policies, request_id, audit handle
}

message PluginResponse {
  optional Secret secret = 1;
  optional Auth auth = 2;
  map<string, bytes> data = 3;
  repeated string warnings = 4;
}
```

The host side of `PluginService` is a Rust trait. Every plugin (WASM or process) implements that trait; the loader picks the right transport.

### Capability-Based Isolation

A plugin only sees what the host explicitly passes in. The protocol defines four **host capability handles** the plugin can invoke:

- `Storage` — barrier-encrypted read/write/list/delete, scoped to the plugin's per-mount UUID prefix. The plugin cannot read another mount's data, cannot escape its prefix, cannot read raw barrier state.
- `Audit` — emit an audit event of a fixed shape. The plugin cannot read prior audit events.
- `Crypto` — host-mediated `bv_crypto` operations (encrypt, decrypt, sign, verify, random). Keys never cross the plugin boundary; the plugin requests an op by `key_handle`. This is how a plugin can sign with the vault's PQC keys without having access to the bytes.
- `Net` — *only present in out-of-process plugins*. WASM plugins have no network capability. Net handles are gated by a per-plugin allowlist (`allowed_hosts: ["*.amazonaws.com"]`) enforced by the host before the connection is opened.

The capability set is **declared** in the plugin's manifest and pinned at registration; widening it requires re-registration.

### Plugin Manifest

Every plugin ships with a manifest the operator pins on registration:

```toml
# plugin.toml
name        = "oracle-database"
version     = "0.4.1"
plugin_type = "database"
runtime     = "wasm"           # or "process"
abi_version = "1.0"             # PluginService major version

[capabilities]
storage = { prefix = "managed", read = true, write = true, list = true }
audit   = { emit = true }
crypto  = { allowed_keys = ["transit:wrapping/oracle-creds"] }
net     = { allowed_hosts = ["*.example-oracle.internal"] }    # process-runtime only

[binary]
sha256 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
size   = 4_532_096
```

The host **refuses to load** a plugin whose binary doesn't match `sha256`. The hash + capability declarations are the trust contract.

### Registration

```
POST /v1/sys/plugins/catalog/<type>/<name>
{
  "version": "0.4.1",
  "runtime": "wasm",
  "binary":  "<base64 of .wasm or path on operator-controlled filesystem>",
  "manifest": "<base64 of plugin.toml>",
  "sha256":  "9f86d081...",
  "signature": "<base64 ML-DSA-65 signature over (binary || manifest)>",
  "signing_key": "transit:plugin-publisher/acme-corp"
}

LIST   /v1/sys/plugins/catalog
GET    /v1/sys/plugins/catalog/<type>/<name>
DELETE /v1/sys/plugins/catalog/<type>/<name>
POST   /v1/sys/plugins/reload/<type>/<name>      # restart all mounts using this plugin
```

Plugins are signed by a **publisher** (a Transit ML-DSA-65 key designated as a plugin-publisher); the host verifies the signature against the operator-configured publisher allowlist before accepting registration. Unsigned plugins are accepted only when `accept_unsigned = true` is set on the engine config (development mode; logged at WARN).

The plugin binary is stored in the barrier — same encryption guarantees as any other secret. On load, the host extracts to a temp file (process runtime) or feeds the bytes directly to `wasmtime::Module::from_binary` (WASM runtime).

### Mount Wiring

Plugins integrate with the existing mount machinery from [docs/secret-engines.md](../docs/docs/secret-engines.md):

```
POST /v1/sys/mounts/oracle-prod
{
  "type": "plugin",
  "config": {
    "plugin_name": "oracle-database",
    "plugin_version": "0.4.1"
  }
}
```

The mount is created exactly like a built-in engine, except the factory closure goes through the plugin loader instead of constructing a Rust struct directly. Per-mount UUID isolation, barrier-encrypted storage view, audit broadcaster, and lease manager all work unchanged — the plugin sees the same `Request`/`Response` shapes that built-in handlers see, just over the wire.

### WASM Runtime

`wasmtime` configured with:
- **No file system** access (no WASI preview1 fs).
- **No clocks beyond `monotonic`** (deterministic time inside the sandbox; real wall-clock is fetched from the host on demand).
- **No network sockets**.
- **Fuel metering** turned on with a per-request budget (default 100M instructions; configurable per plugin). A plugin that exceeds fuel is killed and the request returns a `plugin_timeout` error.
- **Memory limit** (default 256 MiB) enforced via `Store::limiter`.

The host exposes capabilities via `wasmtime::Linker` with one function per protocol message — host functions perform the actual storage / audit / crypto work and pass results back into the WASM linear memory. This is the same pattern used by `wasmtime-wasi` itself.

A small `bastion-plugin-sdk` crate is published for plugin authors:

```rust
use bastion_plugin_sdk::{Plugin, Request, Response, register};

struct OracleDb;
impl Plugin for OracleDb {
    fn handle(&self, req: Request) -> Response { /* ... */ }
}

register!(OracleDb);
```

The `register!` macro emits the WASM `_start` and the protocol-message dispatch glue. Authors target `wasm32-wasi-p2` (component model) or `wasm32-wasi-p1` (preview1) — both are supported.

### Out-of-Process Runtime

For plugins that need real network or system access:

- The host launches the plugin binary with `--bv-plugin-socket=<path>` and a one-time bootstrap token.
- The plugin connects back over the socket; the host establishes a `tonic` server on its side; the plugin runs a `tonic` client. (We could swap host/client; this direction lets the host enforce keepalive + lifecycle.)
- All `PluginService` RPCs flow over the socket. The handshake includes the protocol version + capability assertion; mismatch refuses the connection.
- The plugin process is **supervised**: SIGTERM on cleanup, restart with exponential backoff up to `max_restarts` on crash, log lines (stderr) forwarded into the BastionVault log with a `plugin=<name>` tag.
- The bootstrap token is single-use and rotates on every restart.

`tonic` is pure-Rust and works over Unix-domain sockets / Windows named pipes without TLS (the channel is local + per-process). No TLS overhead, no cert management. Authentication is by socket path + bootstrap token, not by mTLS.

### Versioning

The protocol carries a major.minor version. The host accepts a plugin with the same major and ≤ host's minor. Cross-major incompatibility refuses the load with a clear error pointing the operator at the plugin's compatibility matrix. We commit to **at most one major bump per year** and to **shipping the previous major behind a feature flag for one release after a bump** so plugin authors have a window to migrate.

### Lease, Audit, Crypto Integration

- **Leases** generated by a plugin (e.g. dynamic-DB credentials) flow through the existing lease manager. The plugin's `revoke_handler` is dispatched the same way a built-in engine's would be — by calling `PluginService::HandleRequest` with `operation="revoke"` and the saved internal blob.
- **Audit** events the plugin emits via the host capability are routed through every audit broadcaster the host has configured. The plugin name is added as a field on every event.
- **Crypto** ops via the `Crypto` capability go through the standard `bv_crypto` path — the plugin can request `transit:encrypt(plaintext, key_handle)` without ever seeing the key bytes.

### Hot Reload

`POST /v1/sys/plugins/reload/<type>/<name>` drives:

1. The host acquires a write lock on the plugin's mount instances.
2. For each mount, calls `Cleanup` on the running plugin.
3. Tears down the WASM instance / kills the process.
4. Loads the new binary (already verified at registration).
5. Calls `Initialize` + `Setup` on the new instance.
6. Releases the lock.

In-flight requests are drained before the swap (configurable timeout, default 10s). Requests that arrive during the swap are queued; queued > timeout fail with `plugin_reloading`. This is the right tradeoff because plugin reload is rare and consistency matters more than tail latency for a secrets manager.

### Module Architecture

```
src/modules/plugin/
├── mod.rs                          -- PluginModule; sys path registration
├── catalog.rs                      -- PluginCatalog (registration store)
├── manifest.rs                     -- plugin.toml parser + validator
├── verifier.rs                     -- ML-DSA-65 signature verification + sha256 check
├── capability.rs                   -- Capability declarations + enforcement
├── runtime/
│   ├── mod.rs                      -- PluginRuntime trait
│   ├── wasm.rs                     -- wasmtime backend
│   ├── process.rs                  -- subprocess + tonic backend
│   └── supervisor.rs               -- restart-with-backoff, log forwarding
├── host/
│   ├── mod.rs                      -- host capability dispatch
│   ├── storage.rs                  -- bounded storage view
│   ├── audit.rs                    -- audit emitter
│   ├── crypto.rs                   -- bv_crypto bridge
│   └── net.rs                      -- gated outbound net (process-only)
├── proto/
│   └── plugin_v1.proto             -- the protocol
└── path_*.rs                       -- /v1/sys/plugins/* HTTP path handlers

crates/bastion-plugin-sdk/          -- plugin-author-facing SDK
└── src/
    ├── lib.rs                      -- Plugin trait, register! macro
    └── wasm.rs                     -- WASM runtime glue (cfg(target_arch="wasm32"))
```

Tonic / prost build glue lives in `build.rs` so the `.proto` is the single source of truth.

## Implementation Scope

### Phase 1 — Catalog + Manifest + WASM Runtime — **Done**

| File | Purpose |
|---|---|
| `src/modules/plugin/mod.rs` | Module + `/v1/sys/plugins/*` route registration. |
| `src/modules/plugin/catalog.rs` | Catalog storage + CRUD. |
| `src/modules/plugin/manifest.rs` | `plugin.toml` parser. |
| `src/modules/plugin/verifier.rs` | sha256 + ML-DSA-65 signature verification (reuses Transit). |
| `src/modules/plugin/capability.rs` | Capability declarations + per-call enforcement. |
| `src/modules/plugin/runtime/wasm.rs` | `wasmtime` backend. |
| `src/modules/plugin/host/{storage,audit,crypto}.rs` | Host capability bridges. |
| `src/modules/plugin/proto/plugin_v1.proto` | Protocol schema. |
| `crates/bastion-plugin-sdk/` | Plugin SDK crate. |

Dependencies:

```toml
wasmtime         = { version = "26", default-features = false, features = ["cranelift", "component-model", "addr2line"] }
wasmtime-wasi    = "26"
prost            = "0.13"
prost-types      = "0.13"
tonic            = { version = "0.12", default-features = false, features = ["codegen", "prost"] }
tonic-build      = "0.12"
```

### Phase 2 — Out-of-Process Runtime + Supervisor — **Partial (single-shot only; net allowlist registration check now in place per Phase 5.5; supervisor + tonic still outstanding)**

| File | Purpose |
|---|---|
| `src/modules/plugin/runtime/process.rs` | Subprocess launch + UDS/named-pipe + tonic. |
| `src/modules/plugin/runtime/supervisor.rs` | Restart-with-backoff, log forwarding, health checks. |
| `src/modules/plugin/host/net.rs` | Allowlist-gated outbound networking. |

Dependencies:

```toml
interprocess = "2"               # cross-platform UDS / named pipes
nix          = { version = "0.29", optional = true }   # POSIX signal handling for supervisor
windows-sys  = { version = "0.59", optional = true }   # Windows job objects for child cleanup
```

### Phase 3 — Hot Reload, Versioning, GUI — **Done (drain-and-swap reload via Phase 5.6, signature verification via Phase 5.2, per-plugin Prometheus metrics via Phase 5.10; GUI metrics pivot is Phase 5.12)**

| File | Purpose |
|---|---|
| `src/modules/plugin/path_reload.rs` | `POST /v1/sys/plugins/reload/<type>/<name>`. |
| `gui/src/routes/PluginsPage.tsx` | New page: catalog + register modal + reload button + per-plugin metrics. |
| `gui/src/components/PluginRegisterModal.tsx` | Upload wasm/binary + manifest + signature; preview the manifest before commit. |

### Phase 4 — Reference Plugins — **Done (out-of-tree in `plugins-ext/`); integration tests against the main suite still pending**

To exercise the SDK and the runtime, ship two reference plugins **out-of-tree** (their own repos):

- `bastion-plugin-postgres` — a slim Postgres dynamic-secrets plugin. Demonstrates the WASM runtime since pure-Rust `tokio-postgres` cannot run in WASI yet — the plugin uses the *out-of-process* runtime. (When `wasm32-wasi-p2` gains socket support, we move it to WASM.)
- `bastion-plugin-totp` — a re-implementation of [features/totp-secret-engine.md](totp-secret-engine.md) as a WASM plugin. Demonstrates the WASM runtime. Useful as a porting template.

These prove the protocol is implementable from outside the BastionVault tree.

### Phase 5 — Production-grade gaps — **Mostly done**

| Thread | Status | Scope |
|---|---|---|
| **5.1 Crypto host capability** | **Done** | `bv.crypto_{random,encrypt,decrypt,sign,verify,hmac}` host imports in [`src/plugins/runtime.rs`](../src/plugins/runtime.rs), backed by Transit. `manifest.capabilities.allowed_keys` is enforced literally against the plugin-supplied `transit/keys/<name>` path. Unauthorised keys return `CRYPTO_FORBIDDEN`. The plugin never sees key bytes — the host base64-encodes inputs and decodes outputs around the Transit call. |
| **5.2 ML-DSA-65 publisher signature verification** | **Done** | New [`src/plugins/verifier.rs`](../src/plugins/verifier.rs) verifies on registration *and* every load. Manifest gains `signature` + `signing_key`. Operator-pinned publisher allowlist at `core/plugins/engine/publishers` (HTTP `GET/PUT /v1/sys/plugins/publishers`); engine `accept_unsigned` flag at `core/plugins/engine/accept_unsigned` (HTTP `PUT /v1/sys/plugins/accept_unsigned`; logged at WARN). Canonical signing message: `sha256(binary) || canonical_manifest_json_with_signature_field_stripped`. |
| **5.3 Long-lived supervised process runtime** | **Pending (deferred)** | Replace single-shot `process_runtime` with a long-lived subprocess speaking `PluginService` over UDS / Windows named pipes via `tonic`/`prost`. Single-use 60 s bootstrap token, restart-with-exponential-backoff, log forwarding tagged `plugin=<name>`, health checks. Optional Linux `process_user` for per-plugin uid drop. The current spawn-per-invoke continues to work for "I need real network for one call" cases. |
| **5.4 `PluginService` `.proto` (versioned, shared)** | **Pending (deferred)** | Promote the protocol to a `tonic-build` `.proto` so the WASM ABI and process-runtime gRPC are the same codegen output. Adds host-side `abi_version` major check. |
| **5.5 Net allowlist registration check** | **Done** | `PluginCatalog::validate_net_allowlist` refuses bare `"*"`, port-bearing entries, and `*` outside the leading-label position. (Per-connection enforcement waits on 5.3.) |
| **5.6 Reload drain-and-swap** | **Done** | Per-plugin `tokio::sync::RwLock` in [`src/plugins/reload_lock.rs`](../src/plugins/reload_lock.rs); every invoke takes the read, the reload HTTP handler takes the write with a 10 s drain timeout. On drain timeout the response is `503 plugin_reloading`. Reload swap is audited via the existing `audit.finish` path. |
| **5.7 Quarantined-mount state on plugin delete** | **Done** | New [`src/plugins/quarantine.rs`](../src/plugins/quarantine.rs); `delete` writes a marker at `core/plugins/engine/quarantine/<name>` (timestamp + last-active version) and **preserves** `core/plugins/<name>/data/`. Mounts surface a clear "quarantined: re-register to recover" error. Re-register auto-clears the marker. Operators audit via `GET /v1/sys/plugins/quarantine`. |
| **5.8 Lease renew/revoke plumbing** | **Done** | `translate_response` now parses `secret { lease_id, ttl_secs, renewable, internal_data }` from the plugin's response into `Response.secret: Option<SecretData>` so plugin-issued leases drive the existing lease manager. Renew/revoke dispatch back to the plugin via `build_envelope` was already wired. |
| **5.9 Capability-widening guard** | **Done** | `PluginCatalog::check_capability_widening` refuses any new version that flips `audit_emit` on, adds or moves `storage_prefix` to a non-sub-prefix, or gains an `allowed_keys` / `allowed_hosts` entry. Operators must DELETE + re-register to widen — which audits the change and goes through the quarantine flow. |
| **5.10 Per-plugin Prometheus metrics** | **Done** | New [`src/plugins/metrics.rs`](../src/plugins/metrics.rs) registers `bvault_plugin_invokes_total{plugin, outcome}`, `bvault_plugin_fuel_consumed_total{plugin}`, `bvault_plugin_invoke_duration_seconds{plugin}` with the existing `MetricsManager`. Recorded around every invoke in `PluginLogicalBackend`. GUI-side per-plugin pivot is the remaining sub-thread. |
| **5.11 Reference-plugin integration tests against the main suite** | **Pending** | Exercise `plugins-ext/bastion-plugin-totp` and `bastion-plugin-postgres` from `bastion_vault`'s integration tests (Postgres via `testcontainers`). |
| **5.12 GUI per-plugin metrics surface** | **Pending** | Pivot the new metrics counters into Tauri commands + the existing Plugins page. |

### Not In Scope

- **Native cdylib plugins** (`libloading` / `dlopen`). Explicitly rejected: unstable Rust ABI, no security boundary, version-skew bugs are silent.
- **Java / Python / Go plugins as a first-class runtime.** Plugin authors targeting those languages compile to WASM (Python via `componentize-py`, Go via TinyGo, Java via Wasmer's `JVM-on-WASM`), or use the out-of-process runtime with their language's own gRPC client. We don't ship per-language runtimes in core.
- **Plugin marketplace / centralised registry.** Out of scope; each operator manages their own catalog + publisher allowlist. A future product feature.
- **Cross-plugin inter-communication.** Plugins talk to the host, not each other. If two plugins need to coordinate, the operator wires that through the host (e.g. one writes to a KV path the other reads).
- **Live debugging / attaching to a running plugin.** Out of scope for v1; logs + metrics are the supported observability surface.

## Testing Requirements

### Unit Tests

- Manifest parser: every field in the spec round-trips through parse/serialise; unknown top-level keys are rejected.
- Capability enforcement: a plugin that declares `storage = { write = false }` cannot perform a write — the host returns `permission_denied` before the WASM call returns.
- Signature verifier: a tampered binary fails verification; an unsigned plugin loads only with `accept_unsigned=true`.
- WASM fuel metering: a plugin in an infinite loop is killed at fuel exhaustion; the host returns `plugin_timeout`.
- WASM memory limit: a plugin that allocates past the limit fails cleanly.

### Integration Tests

- Register the reference TOTP plugin (WASM), mount it as `totp/`, generate a code, validate, confirm the result matches the built-in TOTP engine.
- Register the reference Postgres plugin (out-of-process), generate a dynamic credential against a testcontainers Postgres, confirm the user exists and is dropped on revoke.
- Hot reload: register v1 of a plugin, mount it, reload to v2, confirm in-flight requests on v1 finished cleanly and new requests went to v2.
- Crash supervision: kill a process plugin externally; supervisor restarts it within `max_restart_backoff`; subsequent requests succeed.
- Capability escape attempts: a WASM plugin tries to import `wasi_snapshot_preview1::fd_write` (we didn't link it); module instantiation fails with `unknown import`.

### Cucumber BDD Scenarios

- Operator registers the reference Postgres plugin, signed by their internal publisher; mounts it; an application requests credentials and gets a working dynamic user.
- Plugin author publishes v0.5.0; operator verifies the signature against their pinned publisher key; uploads via the GUI; reload completes without dropping in-flight requests.
- A plugin with `storage = { prefix = "tokens", read = true, write = true }` is mounted at `mount-a/`; the plugin attempts to read `mount-b/tokens/foo`; host refuses; audit logs the attempt.

### Negative Tests

- Plugin manifest with `runtime = "process"` and `capabilities.net.allowed_hosts = ["*"]`: rejected (wildcard hosts are refused; an explicit allowlist is mandatory).
- Plugin signed by a key that is not in the configured publisher allowlist: rejected.
- Plugin manifest declaring `abi_version = "2.0"` against a host that supports only major 1: rejected with a compatibility-matrix link.
- Out-of-process plugin that exits with a non-zero code on `Initialize`: registration rolls back; mount creation fails; no orphaned subprocess.

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`**: same constraint as every other module. CI must fail if either becomes reachable.
- **WASM is the security primitive, not the convenience primitive.** A WASM plugin has *no* network, *no* filesystem, *no* clocks beyond monotonic, *no* environment variables. Anything else is requested via host capabilities, which are explicit, auditable, and per-mount.
- **Out-of-process plugins inherit the host's OS user.** A compromised process plugin can do anything that user can. Operators should run BastionVault under a low-privilege user, run process plugins under a *different* low-privilege user when possible (Phase 2 supports `process_user = "bv-plugin-oracle"` on Linux), and confine the BastionVault systemd unit / SCM service with the standard hardening flags.
- **Binary integrity is enforced at registration, not just at load.** The sha256 in the manifest is checked when the binary is uploaded; the manifest is then sealed with the rest of the catalog. A tampered binary on the storage backend is detected on next load (the loader recomputes sha256 against the manifest before instantiation).
- **Signature verification uses Transit ML-DSA-65.** A plugin publisher is a Transit key role; the operator's publisher allowlist references those role names. Compromise of a publisher key is mitigated by the standard Transit rotation: rotate the publisher key, re-sign the catalog, force a reload.
- **Capability widening requires re-registration.** An operator cannot, post-registration, grant a plugin storage write or network access without going through the full register flow (which audits the change and re-verifies the signature).
- **Storage-prefix isolation is enforced by the host, not by the plugin.** The plugin sees a virtual storage view rooted at its declared prefix; it cannot construct a path that escapes (the path is canonicalised + prefix-checked on the host side before the underlying barrier `Get`/`Put`).
- **Audit tagging is non-removable.** A plugin's audit emissions carry the plugin name + version as host-controlled fields; the plugin cannot strip or forge them.
- **Bootstrap token for process plugins is single-use and short-lived (60s default).** A plugin that fails to handshake within the window is killed and the token is invalidated.
- **Reload is auditable.** Every `POST /v1/sys/plugins/reload` event records the actor entity, the old and new versions, and the in-flight request count at swap time.
- **Disabling a plugin does not delete its data.** Mounts using a deleted plugin enter a `quarantined` state; the storage prefix is preserved. This prevents accidental data loss when a plugin is mistakenly removed.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md), and this file's "Current State" / phase markers.
