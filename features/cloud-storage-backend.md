# Feature: Cloud Storage Targets for the Encrypted File Backend

## Summary

Let BastionVault's existing **Encrypted File** storage backend (`src/storage/physical/file.rs`, selected by `storage "file" { ... }` in server config) write its per-key files to a user-owned cloud account — **AWS S3**, **Google Drive**, **Microsoft OneDrive**, or **Dropbox** — instead of (or in addition to) the local filesystem. The on-disk format, the barrier-encrypted `BackendEntry` shape, and the `Backend` trait surface are all unchanged. The cloud is a pluggable **target** underneath the existing file backend, not a new backend.

Earlier drafts of this feature went through two mis-framings that were rejected in review:

1. "Third deployment mode alongside Local / Remote" — overcomplicated (whole-vault rollback manifests, single-writer leases).
2. "Per-file content backend inside `src/modules/files/`" — still the wrong layer; File Resources shouldn't carry the cloud story for every other kind of vault data.

The correct framing is: **the Encrypted File backend writes files somewhere. That somewhere can be `/var/lib/bastionvault/` (today) or an S3 bucket / OneDrive app-folder / Drive app-data folder / Dropbox App Folder (this feature).**

## Status

**Todo — design only.** Nothing implemented yet. Does not depend on File Resources.

## Motivation

- **Bring-your-own-storage.** Operators who already run the vault on a VM they don't want to stake durability on (or who distribute a desktop build via the Tauri GUI) can point the same backend at an S3 bucket or personal cloud drive and get provider-side replication / versioning / retention without vault-side work.
- **Desktop-friendly cross-device vault.** A Tauri-packaged BastionVault desktop app with cloud storage gives one user a vault that works on every machine they sign in from, without running a server.
- **Reuses everything already shipped.** The barrier encrypts and authenticates every file. The `FileBackend`'s key → path mapping already handles arbitrary prefixes. There is nothing cryptographic, nothing schema-level, and nothing routing-level to redesign — only the I/O primitive changes.

Non-goals:

- **Not** a multi-writer story. A cloud target is owned by exactly one BastionVault instance at a time. The single-writer lease scheme from earlier drafts is not needed *for a single-writer deployment*, and multi-writer is out of scope.
- **Not** a transparent cache layer in front of the cloud. Reads go to the cloud; the existing below-barrier `CachingBackend` decorator can be layered on top if the operator enables it, and its ciphertext-only invariant holds unchanged.
- **Not** a way to share the bucket across BastionVault instances. If two processes point at the same target, writes race. A warning in the docs is the full mitigation.

## Current State

Not started. This feature file exists to scope the work before implementation.

## Design

### Where the cloud plugs in

Today `FileBackend` owns one field:

```rust
pub struct FileBackend {
    path: PathBuf,
}
```

…and every CRUD method calls into `std::fs` with paths derived from that root. The refactor replaces the implicit local-filesystem I/O with an explicit trait:

```rust
/// Storage target underneath `FileBackend`. All calls receive the
/// already-computed per-key path (an arbitrary byte string in practice)
/// and the already-serialized `BackendEntry` JSON. The barrier has
/// nothing to do with this layer — values passed in are the exact bytes
/// the caller wants persisted.
#[async_trait]
pub trait FileTarget: Send + Sync + std::fmt::Debug {
    async fn read(&self, key: &str) -> Result<Option<Vec<u8>>, RvError>;
    async fn write(&self, key: &str, value: &[u8]) -> Result<(), RvError>;
    async fn delete(&self, key: &str) -> Result<(), RvError>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, RvError>;
}
```

`FileBackend` becomes:

```rust
pub struct FileBackend {
    target: Arc<dyn FileTarget>,
}
```

The existing body of `FileBackend::get/put/delete/list` moves verbatim into a `LocalFsTarget` that implements the trait. No public API change. Existing `storage "file" { path = "..." }` config still works and continues to hit `LocalFsTarget` under the hood.

### New target kinds

The new config shape:

```hcl
storage "file" {
  target = "local"
  path   = "/var/lib/bastionvault"
}

storage "file" {
  target          = "s3"
  bucket          = "infra-vault"
  region          = "us-east-1"
  prefix          = "bastionvault/"
  credentials_ref = "env:AWS_DEFAULT_PROFILE"
}

storage "file" {
  target          = "onedrive"
  credentials_ref = "keychain:bastionvault/onedrive-refresh"
}
```

Target-specific keys are parsed by the target's own `from_config` constructor; `FileBackend::new` picks the right target based on `target = "..."` and delegates.

`target = "local"` is the default when the field is absent, so every existing config continues to work without edits.

### Providers and auth

| Target | Kind | Auth | Notes |
|---|---|---|---|
| Local | Filesystem | Filesystem permissions | Existing behavior, unchanged. |
| S3 | `aws-sdk-s3` | IAM access key / secret (+ session token) via `credentials_ref`, **or** AWS profile read from the ambient environment. | MinIO-compatible. |
| OneDrive | Microsoft Graph | OAuth 2.0 + PKCE, `Files.ReadWrite.AppFolder` scope. | App-folder sandbox — vault cannot see the rest of the user's OneDrive. |
| Google Drive | Drive v3 | OAuth 2.0 + PKCE, `drive.appdata` scope. | App-data folder sandbox. |
| Dropbox | Dropbox v2 | OAuth 2.0 + PKCE, App Folder scope. | App-folder sandbox. |

**BastionVault does not ship shared OAuth client secrets for consumer providers.** Each distribution or operator configures their own `client_id` at build or runtime, per provider guidance for redistributable-but-not-hosted applications.

### `credentials_ref` and OAuth persistence

Cloud targets accept a `credentials_ref` string in a small URI grammar:

- `env:<VARNAME>` — read credentials from an environment variable.
- `keychain:<label>` — read from the OS keychain (Tauri desktop mode).
- `file:<path>` — read from a local file owned by the process.
- `inline:<base64>` — literal embedded credential (rejected in production-strict mode; useful for tests only).

For OAuth-based targets, the *refresh token* is what sits at `credentials_ref`. The vault admin runs a one-shot OAuth flow (see below) that writes the refresh token to the configured ref. The target's runtime code uses the refresh token to get fresh access tokens on demand.

The OAuth flow runs through the CLI and GUI:

- **CLI**: `bvault operator cloud-target connect --target=<name>` opens the consent URL in the system browser, listens on a loopback port for the callback, exchanges the code, and writes the refresh token to `credentials_ref`.
- **GUI**: Settings → Storage → "Connect" button kicks off the same flow in the system browser and shows the bound account on completion.

Reauth when the refresh token dies is the same flow; the target marks itself `needs-reauth` and subsequent operations fail with a clear error that points at the remediation.

### Operational semantics

- **Single writer per target.** Running two BastionVault processes against the same bucket + prefix is supported but not defended: writes race, and the last writer wins. The docs warn explicitly. For HA across multiple hosts, use the Hiqlite backend, which is what it's for.
- **Freshness.** The cloud is an object store; eventual consistency on list/read varies by provider (S3 is now strong-read-after-write; consumer drives have sync delays up to minutes). The vault reads through `Backend::get` on every request unless caching is enabled; there is no cross-node invalidation. This is the same property as running `FileBackend` off a shared NFS mount and is already understood.
- **No tombstone / snapshot / rollback protection at the cloud layer.** The barrier's existing integrity surface applies unchanged. A provider that rolls back an individual object is detected on decrypt (AEAD tag mismatch would be one path; an unexpected plaintext shape after decrypt is another); whole-target rollback to a consistent earlier snapshot is the intrinsic limit of untrusted storage without a trusted counter, and we document it.
- **Listing.** `Backend::list(prefix)` maps to the provider's prefix+delimiter list API. Consumer drives that don't support a `delimiter` concept (Dropbox v2 does; others vary) simulate it client-side.

### Key-name handling

Local `FileBackend` URL-encodes tricky characters in keys before using them as filenames. Cloud object stores accept most bytes in keys, so the `LocalFsTarget` keeps its URL-encoding and the cloud targets pass keys through. Operators who want cloud object keys to be opaque (the rough shape of vault activity is visible to anyone with bucket read access, even if the ciphertext isn't) can enable **key obfuscation**:

```hcl
storage "file" {
  target          = "s3"
  obfuscate_keys  = true
  ...
}
```

When on, the object key is `HMAC-SHA256(target_salt, raw_key)` hex-encoded. `target_salt` lives in a dedicated `<prefix>/_salt` object (itself encrypted by the barrier like any other vault key) and can be rotated via a dedicated rekey job that rewrites every object key in the bucket. Off by default.

### Failure modes

- **Provider unreachable on read**: `Backend::get` returns `RvError::ErrOther` wrapping the transport error. The request fails clean.
- **Provider unreachable on write**: same. Vault-side, the write is durable iff the target reports success.
- **429 / throttling**: exponential backoff with jitter inside each target. Capped retry count. Failure surfaced clearly so the operator can diagnose.
- **OAuth refresh failure**: target enters `needs-reauth`; subsequent operations fail with a specific error pointing at the reconnect flow.
- **Credential expiry mid-operation**: transparent refresh on the first 401; one retry; then fail.

### Performance

- **Round-trip cost dominates.** For latency-sensitive deployments, layer the existing `CachingBackend` decorator on top (`cache.secret_cache_ttl_secs > 0` in server config). Its ciphertext-only invariant holds — the cache sees the same bytes the cloud sees.
- **Parallel prefetch** on startup for vault paths known to be hot (policies, mounts). Target-level optimization, not required for correctness.
- **Multipart upload** for S3 / Drive when a single `put` exceeds 5 MiB (unlikely for vault keys — most are under a few KiB — but allocating under 5 MiB is cheap and over 5 MiB needs multipart on S3). Later optimization.

## New crate layout

Narrow crates per `agent.md` guidance:

```
crates/
  bv_file_targets/
    src/
      lib.rs            # FileTarget trait + target-kind enum + from_config entry
      local.rs          # moved from src/storage/physical/file.rs
      s3.rs             # aws-sdk-s3 impl
      onedrive.rs       # Microsoft Graph impl
      gdrive.rs         # Drive v3 impl
      dropbox.rs        # Dropbox v2 impl
      oauth.rs          # shared PKCE + loopback-redirect flow
      creds.rs          # credentials_ref resolver (env / keychain / file / inline)
```

Feature-gated at the top level so operators who don't need cloud targets pay no compile or binary-size cost:

```toml
[features]
cloud_s3       = ["bv_file_targets/s3"]
cloud_onedrive = ["bv_file_targets/onedrive"]
cloud_gdrive   = ["bv_file_targets/gdrive"]
cloud_dropbox  = ["bv_file_targets/dropbox"]
cloud_targets  = ["cloud_s3", "cloud_onedrive", "cloud_gdrive", "cloud_dropbox"]
```

The top-level `bastion_vault` crate gains a thin wrapper that constructs the configured target in `FileBackend::new`.

## Migration from the current `FileBackend`

Zero for operators who don't change their config: `target = "local"` is the default and the existing code path is preserved bit-for-bit.

Moving an existing vault to a cloud target uses the existing `operator migrate` CLI (`src/cli/command/operator_migrate.rs`) which already performs backend-to-backend copy at the physical layer. Register a second `storage "file"` stanza with the cloud target, run `bvault operator migrate --source=<local> --dest=<cloud>`, then swap the active config. No special migration code needed.

## GUI

- **Settings → Storage** — current mode (local path / cloud provider + bucket) and a "Change" action. The change flow kicks off the backend-migrate command under the hood and shows progress.
- **Cloud OAuth connect UI** — provider picker → consent browser → "Connected as `user@example.com`" confirmation on return. Identical shape to the `bvault operator cloud-target connect` CLI flow.

## Phases

| # | Phase | Scope |
|---|-------|-------|
| 1 | `FileTarget` abstraction + `LocalFsTarget` | Refactor `FileBackend` to hold `Arc<dyn FileTarget>`, move existing body into `LocalFsTarget`, prove zero regression on every existing test. No new behavior. |
| 2 | S3 target | `S3Target` against `aws-sdk-s3`. `credentials_ref` resolver. MinIO-based integration tests. |
| 3 | OAuth infrastructure | PKCE + loopback-redirect flow in `bv_file_targets::oauth`. Used by Phases 4-6. CLI `bvault operator cloud-target connect`. |
| 4 | OneDrive target | Microsoft Graph + `Files.ReadWrite.AppFolder`. |
| 5 | Google Drive target | Drive v3 + `drive.appdata`. |
| 6 | Dropbox target | Dropbox v2 + App Folder. |
| 7 | GUI | Settings → Storage page; Connect flow in the system browser. Tauri desktop mode reuses the OS keychain for the refresh token. |
| 8 | Key obfuscation + rekey | `obfuscate_keys = true` toggle. Rekey job that rewrites every object under a new salt. |

Phase 1 is the critical path — it is a pure refactor with no functional change, and it must land green before any cloud code is merged. Phases 4-6 parallelize after Phase 3 lands the OAuth infra.

## Testing Requirements

- **Phase 1 regression**: every existing `FileBackend` test passes unchanged against the new `FileBackend { target: Arc<LocalFsTarget> }` shape. No behavior difference.
- **S3 integration**: MinIO in CI. Full CRUD round-trip, list-with-prefix, byte-for-byte integrity, chunked-reads-and-writes.
- **Consumer-drive integration**: record-and-replay HTTP fixtures in CI; nightly live-tape against dedicated test accounts to refresh fixtures.
- **Security regression**: `cloud_target_never_sees_plaintext` — drive a `BackendEntry::put` through a wrapped `FileBackend` whose target records the exact bytes it was asked to write. Assert those bytes do not contain a known plaintext marker that was encrypted by the barrier above.
- **Failure injection**: 429 / 503 / timeout on each verb per provider; assert retry-with-backoff and clear surfaced errors.
- **Backend-migrate compatibility**: round-trip a vault through `operator migrate` local → S3 → local; assert every key's value is byte-identical at the barrier layer.
- **OAuth flow**: loopback-redirect port open-release; PKCE code verifier correctness; refresh-token persistence via every `credentials_ref` kind.

## Security Considerations

- **Provider never sees plaintext.** Values handed to `FileTarget::write` are barrier-encrypted `BackendEntry` JSON — the same bytes currently written to local disk. Decryption happens in the barrier above `FileBackend`; the target is below the barrier.
- **Keys-as-metadata.** Object keys reveal the rough shape of vault activity (which paths exist, how often they change) to anyone with bucket read access. The barrier does not cover key names. Operators who need to hide this turn on `obfuscate_keys`; they accept that out-of-band bucket inspection becomes harder in exchange.
- **Credentials.** Cloud target credentials are referenced, not inlined. OAuth refresh tokens live in the OS keychain (desktop) or a file owned by the vault process (server). Rotating a refresh token does not require a vault restart.
- **Scope boundaries.** OAuth scopes are the narrowest available: app-folder / app-data for consumer drives; IAM policy guidance in docs restricts S3 to the specific bucket + prefix.
- **No client-secret redistribution.** Each operator or distribution provides their own `client_id` and secret where applicable.
- **Feature-gated.** A build without `cloud_targets` cannot accidentally contact a cloud provider.
- **Single-writer assumption documented.** Two BastionVault processes against the same target + prefix produce racing writes. The docs say so loudly; the code does not attempt to arbitrate.

## Open Questions (resolved before Phase 1)

1. Whether to parse the full config into a `TargetKind` enum at `FileBackend::new` time, or keep it fully dynamic via `Arc<dyn FileTarget>`. Leaning `Arc<dyn>` for pluggability; the static-dispatch alternative saves one virtual call per operation which is negligible at cloud latencies.
2. Whether `credentials_ref = "keychain:..."` is available on Linux via `secret-service`, or gated to macOS / Windows where the platform keychain is more reliable. Leaning "available everywhere, operator chooses `file:` on Linux if `secret-service` isn't running."
3. Whether the `FileTarget` trait should also expose a bulk-delete primitive that S3 / Dropbox can implement efficiently, or whether per-object deletes in a loop are acceptable in v1. Leaning per-object for simplicity; bulk-delete as a later optimization.
