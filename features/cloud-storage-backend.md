# Feature: Cloud Storage Backend

## Summary

Add a third deployment mode for BastionVault alongside **Local (Embedded)** and **Remote (Connect to Server)**: **Cloud**, where the vault's ciphertext-at-rest lives in a user-provided cloud object store. Initial providers: **AWS S3**, **Google Drive**, **Microsoft OneDrive**, **Dropbox**.

The vault barrier and key management remain unchanged. Only the physical `Backend` trait gets new implementations. Plaintext never leaves the client; the cloud provider sees only opaque, authenticated ciphertext produced by the existing ChaCha20-Poly1305 barrier.

## Status

**Todo — design only.** Nothing implemented yet. This document captures the intended design so it can be reviewed before code lands.

## Motivation

- **Portability without a server**: users who want their secrets available across devices today must either run a network-reachable BastionVault server (Remote mode) or synchronise the local data directory manually. A cloud backend removes that friction while keeping the server-less UX of Embedded mode.
- **Backup-by-construction**: the provider's durability and versioning become the disaster-recovery story for solo users.
- **Bring-your-own-storage**: keeps BastionVault free of any hosted service of its own. Each user authenticates to their own S3 bucket or personal cloud drive.

Non-goals:

- This is **not** a multi-writer HA mode. For shared/team deployments, Remote mode with a Hiqlite cluster remains the answer. See *Concurrency* below.
- This is **not** a way to share secrets between users. Sharing continues to flow through the normal identity/ACL layer on a running vault.
- The cloud provider is **never** trusted with plaintext or keys. A compromised provider account must not be able to read secrets — only to deny service or roll back state (see *Threat Model*).

## Current State

Not started. This feature file exists to scope the work before implementation.

## Design

### Deployment Mode (GUI)

`InitPage` and `SettingsPage` today present two modes: `Embedded` and `Remote`. Add a third: `Cloud`.

```
( ) Local (Embedded)      -- data in app-data dir, this machine only
( ) Connect to Server     -- remote HTTPS API
( ) Cloud Storage         -- data in your cloud account (S3 / OneDrive / Drive / Dropbox)
```

Cloud mode runs the **same embedded vault** as Local mode; the only difference is the `Backend` implementation wired under the barrier. Init/unseal/root-key handling is identical to Embedded mode and still uses the OS keychain for the unseal key.

### Storage Model

The vault's `Backend` trait exposes `list / get / put / delete` over hierarchical keys. Cloud object stores are flat key-value stores with a `/` convention — a near-perfect fit.

- **Key → object name**: the vault key is used verbatim as the object key, with `core/` `sys/` `logical/` etc. prefixes preserved. A single configurable root prefix (e.g. `bastionvault/`) isolates vault data from anything else in the same bucket/folder.
- **Value**: raw ciphertext bytes as produced by the barrier. No JSON wrapping on the wire for object-store backends — the barrier already serialises `BackendEntry`. *(Open question: keep the current JSON `BackendEntry` envelope for parity with `FileBackend`, or strip it. See* Decisions To Make *below.)*
- **Listing**: use the provider's prefix+delimiter listing API. `list("foo/")` maps to `prefix=bastionvault/foo/`, `delimiter=/`. Return immediate children with a trailing `/` for directories, bare names for objects, mirroring `FileBackend`.

No directory objects are created. Absence of a common prefix means absence of children, as in S3.

### New Crate Layout

Per `agent.md` guidance on narrow crates, introduce:

```
crates/
  bv_cloud_storage/
    src/
      lib.rs            # re-exports + common types (CloudError, CloudCreds)
      s3.rs             # S3Backend (aws-sdk-s3)
      onedrive.rs       # OneDriveBackend (Microsoft Graph)
      gdrive.rs         # GoogleDriveBackend
      dropbox.rs        # DropboxBackend
      oauth.rs          # shared OAuth2 PKCE flow for the three consumer drives
      cache.rs          # optional LRU of recent gets (ciphertext-only)
```

Each provider exposes a single `Backend` impl. All providers share:

- An `async` HTTP client (`reqwest` with rustls — already a workspace dep).
- A retry/backoff policy with jitter for 429/5xx.
- A conditional-write primitive (ETag/If-Match for S3, `@microsoft.graph.conflictBehavior` for OneDrive, `rev` for Dropbox, `ifMetadataMatches` for Google Drive) used to implement a single-writer lease (see *Concurrency*).

Feature-gated in the top-level crate so users who don't need cloud pay no compile-time or binary-size cost:

```toml
[features]
storage_s3       = ["bv_cloud_storage/s3"]
storage_onedrive = ["bv_cloud_storage/onedrive"]
storage_gdrive   = ["bv_cloud_storage/gdrive"]
storage_dropbox  = ["bv_cloud_storage/dropbox"]
storage_cloud    = ["storage_s3", "storage_onedrive", "storage_gdrive", "storage_dropbox"]
```

Wire each provider into `storage::new_backend` behind its feature, matching the pattern already used for `storage_mysql` / `storage_hiqlite`.

### Credentials & OAuth

- **AWS S3**: accept either (a) an IAM access key / secret / session token, or (b) an AWS profile name resolved via the standard SDK credential chain. No BastionVault-managed OAuth. Region + bucket + optional prefix + optional KMS key ARN are config.
- **OneDrive / Google Drive / Dropbox**: OAuth 2.0 with PKCE. The GUI opens the system browser, the user grants access, and the callback returns via a loopback redirect (`http://127.0.0.1:<ephemeral>/callback`). Refresh tokens and access tokens are stored in the **OS keychain**, never on disk in plaintext. Scopes are the narrowest the provider offers (app-folder scope for OneDrive / Drive / Dropbox where available, so the vault cannot see or touch the rest of the user's files).
- **BastionVault does not ship its own OAuth client secrets for consumer providers.** Each build or distribution configures its own client IDs (for consumer-drive providers that require one) at compile time, or the user pastes their own. This avoids a shared-secret problem if the binary is redistributed.

### Threat Model

The cloud provider is **semi-trusted**:

- Confidentiality: guaranteed by the barrier. All bytes written to the cloud are ciphertext under a key the provider never sees. A full provider compromise leaks metadata (key names, sizes, write timestamps) but not secret values.
- Integrity: each object is authenticated by the AEAD tag inside the barrier payload. A provider cannot tamper with a value without detection on read.
- Freshness / rollback: an object-store provider *can* roll an object back to an earlier ciphertext version, or drop writes. Barrier-level freshness is **not** currently enforced. Mitigations:
  - Maintain a signed manifest object (`_manifest`) listing every live key and its latest ciphertext hash, rewritten on every commit. A rollback of an individual object is detected because its hash won't match the manifest.
  - The manifest itself is signed with ML-DSA-65 (reusing the PQ signing material the vault already manages), so the provider cannot forge one.
  - Rollback of the manifest itself to a *consistent* earlier state (all objects + manifest from some past snapshot) remains possible and is called out explicitly in the docs. This is the intrinsic limit of untrusted storage without a trusted counter.
- Metadata: key names are sensitive (they encode mount paths and sometimes principal names). For providers that support it, wrap each key name through a deterministic keyed hash (HMAC over a stable key derived from the unseal secret) so the cloud sees opaque identifiers. Listing maps the hashed names back using a per-mode local index that lives inside the vault itself. This is optional (config flag `obfuscate_keys=true`) because it breaks out-of-band inspection of the bucket.

### Concurrency

Cloud mode is **single-writer**. Attempting to run two vault processes against the same bucket is a supported-but-guarded scenario, not an HA configuration.

- On unseal, the vault acquires a **lease object** (`_lease.json`) by conditional create (`If-None-Match: *` on S3; analogous on each provider). The lease contains a random lease ID, the holder's hostname, and an expiry timestamp.
- The holder refreshes the lease every 30 s with a conditional update (`If-Match: <etag>`).
- Writes attach `If-Match: <lease-etag>` semantics via the manifest: every commit rewrites `_manifest` with `If-Match`. A stale writer's commit fails and the process seals itself.
- On clean shutdown the lease is released. On crash the expiry (default 2 min) lets another process take over.

For users who genuinely need multi-writer access across machines, the answer remains: run a BastionVault server (Remote mode), possibly backed by Hiqlite HA. This is documented prominently.

### Performance

Object-store latency is dominated by round-trips. The vault currently does many small reads during unseal and policy evaluation. Without care, cloud mode will feel orders of magnitude slower than Embedded.

- **Read cache**: in-memory LRU of recent `get` results, keyed by `(key, etag)`. Invalidated on any local `put/delete`. Cache holds ciphertext only, so a memory dump contains no more than the cloud already stores.
- **Manifest piggyback**: since the manifest enumerates live keys and their hashes, a cold start pulls the manifest once and uses it to short-circuit `get` for absent keys without a round-trip.
- **Batched writes**: where the provider supports multi-object commit (S3 does not; Drive/OneDrive/Dropbox have batch endpoints), coalesce burst writes within a 50 ms window. Optional; default off.

These optimisations are additive and can land after a correct but slow first cut.

### Configuration

Server config (`hcl`) gains:

```hcl
storage "s3" {
  bucket = "my-vault"
  region = "us-east-1"
  prefix = "bastionvault/"
  # credentials: env / profile / inline
}

storage "onedrive" {
  folder = "BastionVault"
  # tokens loaded from keychain
}
```

GUI cloud-mode setup writes equivalent config into the embedded vault's data dir.

### Migration

Users on Embedded or Remote mode can move to Cloud mode (and back) via the existing **operator migrate** tool (`src/storage/migrate.rs`, `src/cli/command/operator_migrate.rs`), which already performs backend-to-backend copy at the physical layer. Add cloud backends to its supported source/destination set. No new migration tool needed.

The GUI gains a "Migrate to cloud…" action in Settings that wraps the CLI path.

## Decisions To Make Before Implementation

1. **Wire format**: keep `BackendEntry` JSON envelope (matches `FileBackend`, simplifies migrate tool) or strip to raw ciphertext (smaller, cleaner)? Leaning toward keeping JSON for v1 to minimise surprises in the migrate path.
2. **Key-name obfuscation default**: off (easier to debug, matches S3-console expectations) or on (better metadata posture). Leaning toward **off by default, on by config** to match the project's "explicit over clever" stance.
3. **Consumer-drive OAuth client IDs**: require the user to provide their own, or ship per-distribution defaults? Shipping defaults is friendlier; requiring user-provided is safer. Leaning toward user-provided with a documented walkthrough.
4. **Rollback detection scope**: manifest-based only (proposed), or also a monotonic epoch counter? A counter adds complexity but catches whole-bucket rollback. Defer unless a reviewer pushes back.

## Phases

| # | Phase | Scope |
|---|-------|-------|
| 1 | S3 backend | `S3Backend` + `If-Match` conditional writes + manifest + lease. Feature-flag `storage_s3`. CLI config. Migrate-tool integration. |
| 2 | Lease/manifest hardening | Rollback-detection tests. Crash-recovery tests. Lease-takeover tests. Fault injection (provider 5xx, 429). |
| 3 | GUI cloud mode (S3) | Third radio on `InitPage`/`SettingsPage`. Credential entry. Setup wizard writes config. E2E test with a local MinIO. |
| 4 | OneDrive backend | Graph API client, OAuth-PKCE flow, app-folder scope, ETag-based conditional writes. Keychain token storage. |
| 5 | Google Drive backend | Drive v3 client, OAuth-PKCE, app-data folder scope, `ifMetadataMatches`-based conditional writes. |
| 6 | Dropbox backend | Dropbox API v2, OAuth-PKCE, App Folder scope, `rev`-based conditional writes. |
| 7 | GUI consumer-drive wiring | Browser OAuth launch, callback handling, provider picker in the setup wizard. |
| 8 | Performance pass | Read cache, manifest-driven negative cache, optional write batching. Benchmarks vs. FileBackend. |

Phase 1 is the critical path and the biggest security surface. Phases 4–6 are largely parallelisable after Phase 2 lands.

## Testing Requirements

- **Unit**: backend CRUD against a mocked HTTP layer per provider. Malformed manifest, missing manifest, stale ETag, expired lease.
- **Integration**:
  - S3: against MinIO in CI.
  - OneDrive / Drive / Dropbox: against a recorded-tape HTTP fixture (no live calls in CI). A nightly live-tape refresh job with dedicated test accounts.
- **Fault injection**: provider returns 429/503/timeouts; verify exponential backoff, eventual success, no silent data loss.
- **Compatibility**: a vault initialised with `FileBackend`, migrated to `S3Backend` via `operator migrate`, then unsealed, must read back every prior secret byte-for-byte.
- **Rollback detection**: given an artificially rolled-back object, a read must surface a distinct, loud error (not silent stale data).
- **Security regression**: no plaintext ever appears in HTTP request bodies observed by the test harness. Enforced by a capture-and-scan test.

## Operational Safety Notes

- Cloud mode is marked **Experimental** in the GUI and docs until Phase 2 ships with its test suite green.
- The GUI warns at setup that losing access to the cloud account or the local unseal key means losing the vault; a printable recovery sheet is offered (same flow as Embedded mode).
- The sealed-vault-can-be-read invariant holds: an attacker with the cloud bucket but without the unseal key sees only ciphertext.
- Audit events emit the backend type (`s3`, `onedrive`, `gdrive`, `dropbox`) on every unseal so operators can see in the audit log that a vault is running against cloud storage.
