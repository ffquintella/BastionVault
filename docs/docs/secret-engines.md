---
sidebar_position: 10
title: Secret Engines
---

# How Secret Engines Work

A "secret engine" in BastionVault is a **logical backend** mounted at a path prefix, behind a uniform request/response router, with its own storage namespace inside the encrypted barrier. The model mirrors HashiCorp Vault's: type registration → mount → request routing → backend handler → barrier-encrypted storage.

## 1. The `Module` trait — registration

Every engine lives under `src/modules/<name>/` and implements the `Module` trait in `src/modules/mod.rs`:

```rust
pub trait Module: Any + Send + Sync {
    fn name(&self) -> String;
    fn as_any_arc(...) -> Arc<dyn Any + Send + Sync>;
    async fn init(&self, _core: &Core) -> Result<(), RvError> { Ok(()) }
    fn setup(&self, _core: &Core) -> Result<(), RvError> { Ok(()) }
    fn cleanup(&self, _core: &Core) -> Result<(), RvError> { Ok(()) }
}
```

`setup()` is where an engine **registers a factory** with the core:

```rust
// from src/modules/kv/mod.rs
core.add_logical_backend("kv", Arc::new(kv_backend_new_func))
```

That hands `Core` a closure `Fn(Arc<Core>) -> Arc<dyn Backend>`. The string `"kv"` is the **type name** — not a mount path. One factory can produce many backend instances, one per mount.

The full set of engine modules is declared in `src/modules/mod.rs`: `auth`, `credential`, `crypto`, `files`, `identity`, `kv`, `kv_v2`, `pki`, `policy`, `resource`, `resource_group`, `system`. Of those, the user-facing **secret engines** are `kv`, `kv_v2`, `crypto`, `files`, `pki`, `resource`, plus `system` (which exposes vault management endpoints).

## 2. The `LogicalBackend` — declarative routes

Engines build their HTTP surface declaratively with the `new_logical_backend!` macro:

```rust
new_logical_backend!({
    paths: [{
        pattern: ".*",
        fields: { "ttl": { field_type: FieldType::Int, ... } },
        operations: [
            {op: Operation::Read,   handler: kv_backend_read.handle_read},
            {op: Operation::Write,  handler: kv_backend_write.handle_write},
            {op: Operation::Delete, handler: kv_backend_delete.handle_delete},
            {op: Operation::List,   handler: kv_backend_list.handle_list}
        ],
        help: "..."
    }],
    secrets: [{
        secret_type: "kv",
        renew_handler: ...,
        revoke_handler: ...,
    }],
    help: KV_BACKEND_HELP,
});
```

Three pieces matter:

- **`paths`** — regex pattern + per-field schema + per-operation handler. The router does Vault-style longest-prefix mount matching, then per-mount regex matching, then dispatches to the handler that matches the HTTP verb (mapped to `Operation::{Read,Write,List,Delete}`).
- **`fields`** — typed schema; the framework parses, validates, and coerces the request body before the handler sees it.
- **`secrets`** — declares **secret types** the engine issues (e.g. `"kv"` leases). Each secret type registers `renew_handler` and `revoke_handler` so the **lease manager** can call back when a TTL is renewed or a lease is explicitly revoked.

## 3. Mounting — where it lives in the URL space

`add_logical_backend` only registers the **type**. To get an engine onto a path you mount it. The mount infrastructure is in `src/mount.rs`, owned by `Core`:

- `Core` holds `pub mounts_router: Arc<MountsRouter>`.
- On unseal, `mounts_router.load_or_default(...)` reads the **mount table** out of the barrier (so mounts persist across restarts), then `setup()` materialises one backend instance per mount entry by calling the registered factory.

A mount is an entry in `MountTable` with: `path` (e.g. `secret/`), `type` (e.g. `kv`), `uuid`, `description`, and `config` (default/max lease TTL, audit options, options map). Each mount gets:

- A **storage view** scoped under `LOGICAL_BARRIER_PREFIX/<uuid>/` so two `kv` mounts never see each other's keys, and an attacker reading raw storage cannot tell mounts apart by path.
- A **system view** for reading mount-specific config.
- Its own **router entry** so an HTTP request to `/v1/secret/foo/bar` routes to that backend with `req.path = "foo/bar"` (mount prefix stripped).

System mounts (`sys/`, `auth/`, `identity/`) live under `SYSTEM_BARRIER_PREFIX` and are managed by `system` module endpoints.

## 4. Request lifecycle

For an HTTP call like `POST /v1/secret/data/db creds=...`:

1. **HTTP layer** (`src/http/`) parses the request, authenticates the token, and attaches policies.
2. **Router** finds the mount whose path is the longest prefix of `/secret/data/db`, strips the mount prefix, and looks up the backend.
3. **Backend** matches `data/db` against its `paths` regex table, picks the `Operation::Write` handler, parses fields per the schema.
4. **Handler** runs (e.g. `KvBackendInner::handle_write`), which calls `req.storage_put(...)`. `storage_put` writes through the **barrier**, which transparently encrypts with ChaCha20-Poly1305 before hitting the physical store (file / MySQL / Hiqlite).
5. If the response declares a `Secret`, the **lease manager** assigns a lease ID, persists lease metadata, and schedules expiry. Renew/revoke later call back into the engine's registered handlers.
6. **Audit** broadcasters log the request and response, with sensitive fields HMAC'd, not raw.

Reads are symmetric: the router strips the mount prefix, the handler calls `req.storage_get(...)`, the barrier decrypts, and the engine shapes a `Response`.

## 5. Storage isolation — the barrier + per-mount view

Two layers stack:

- **Barrier** (`src/storage/barrier_*.rs`): every `Get`/`Put`/`Delete` is encrypted. Plaintext keys never touch disk. The barrier's data encryption key is wrapped by the KEK reconstructed at unseal time.
- **StorageView**: each mount sees only its `logical/<uuid>/` slice. The view rewrites paths transparently so engine code can pretend it owns the whole keyspace.

This is why you can mount `kv` twice (`secret/` and `team-a/`) without collision, and why deleting a mount can wipe its data by removing one prefix.

## 6. Engines available today

| Module | Type name | What it does |
|---|---|---|
| `kv` | `kv` | v1 generic K/V — pass-through to barrier-encrypted storage with optional lease TTL. |
| `kv_v2` | `kv-v2` | Versioned K/V with soft-delete metadata; adds `metadata.rs` and `version.rs` alongside `mod.rs`. |
| `crypto` | encryption-as-a-service | Wraps `bv_crypto` (ML-KEM, ML-DSA, AEAD) for callers that don't want to manage keys. |
| `files` | file resources | Binary blob storage with metadata, used by the GUI's file manager. |
| `resource` / `resource_group` | typed records | Structured "resource" records (think SSH targets, DB creds metadata) and groups thereof. |
| `pki` | (disabled stub today) | The legacy X.509 engine; will return on a pure-Rust, PQC-capable stack — see the PKI feature spec. |
| `system` | `sys` | Mount management, init/seal/unseal, policy CRUD, leases, capabilities — the control plane. |
| `policy` | — | Policy storage + ACL evaluation. Not a "mounted engine" the way `kv` is; consumed by the auth pipeline. |
| `identity` | — | Entities, aliases, groups; mounted at `identity/`. |
| `auth` / `credential` | auth backends, not secret engines | Same trait machinery but mounted under `auth/` and produce tokens, not secrets. |

## 7. Adding a new engine — concretely

1. Create `src/modules/<name>/mod.rs` with a struct holding `Arc<Core>`.
2. Implement `Module`. In `setup()`, build a `LogicalBackend` via `new_logical_backend!`, expose a factory closure, and call `core.add_logical_backend("<type>", factory)`.
3. Implement handlers (`async fn(&self, &dyn Backend, &mut Request) -> Result<Option<Response>, RvError>`); use `req.storage_*` to persist through the barrier.
4. If the engine issues leases, declare `secrets: [...]` and implement `renew_handler` / `revoke_handler`.
5. Register the module in `src/modules/mod.rs` and have `Core::new` instantiate it (look for where `KvModule::new` is invoked).
6. Once registered, operators mount it via `POST /v1/sys/mounts/<path>` with `{"type": "<name>"}` — the mount table picks up the factory and creates the per-mount backend instance on the spot.

The PKI rewrite follows exactly this pattern: a `PkiModule` registers type `"pki"`, path file modules (`path_roles.rs`, `path_issue.rs`, ...) build the route table, the `CertSigner` trait sits behind the handlers, and CA private keys are stored through the barrier just like any other engine's data.
