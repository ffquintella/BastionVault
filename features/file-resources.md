# Feature: File Resources

## Summary

A new resource kind that stores **files** — arbitrary binary blobs with filename, MIME type, size, and integrity metadata — under the vault barrier alongside secrets. Files inherit the existing per-user-scoping model (ownership, sharing, ACLs, audit). Phase 1 stores files locally in the vault backend the same way KV secrets do. Later phases add **SMB**, **SCP**, and **SFTP** sync targets so the vault can mirror file content out to (or import from) a network share.

## Status

**Done — Phases 1–6 + 8 shipped.** Phase 5 (SMB) lands behind the `files_smb` Cargo feature using `smolder-smb-core` (pure-Rust SMB2/3 + NTLM, no `libsmbclient` C dep). Phase 6 (SFTP + SCP) lands behind the `files_ssh_sync` Cargo feature using `russh` 0.45 + `russh-sftp` 2 (pure-Rust SSH client; same dep tree the planned Resource Connect SSH window will reuse). Phase 7 (periodic re-sync) remains deferred — see "Deferred sub-initiatives" at the bottom of this file.

## Motivation

BastionVault today stores short, structured secrets (passwords, tokens, API keys). Operators regularly also need to manage **file-shaped artifacts** tied to the same infrastructure resources:

- SSH private keys, CA bundles, client PKCS#12 / PFX bundles, Kerberos keytabs.
- Cloud provider service-account JSON.
- Config files with embedded secrets (haproxy, nginx, Postgres `pg_hba.conf`).
- License files, code-signing keys, HSM PINs in small text files.

Today these are either base64-stuffed into KV values (fragile, size-limited, awkward) or kept out-of-band (defeats the vault). A first-class file type removes the awkwardness and keeps the barrier's confidentiality + integrity guarantees.

The sync-target feature addresses a second pain point: operators often want the file both in the vault *and* deployed to a target machine (SSH key on a jump host, cert bundle on a web server). Today that's a manual copy. A sync target lets the vault push (or pull) the file to a specified path on a remote system, with the vault as the source of truth.

Non-goals:

- **Not** a general-purpose file server or cloud drive. Files are infrastructure artifacts, not user documents.
- **Not** a CDN. Scale is hundreds to low thousands of files per deployment, each up to a bounded size (see *Size limits* below).
- **No** file previews beyond a plain-text viewer in the GUI. The vault is not in the business of rendering PDFs or images.

## Current State

**Phases 1 + 2 + 3 + 4 + 8 shipped** (GUI carries Files page + per-file Info / Sync / Versions tabs + Edit modal + drag-and-drop upload with Windows/WebView2 drop-handler fix; resource-detail pages grew a Files tab listing files associated with each resource; Admin → Audit aggregates file lifecycle events). Asset-group membership for files is wired through a third reverse index in `ResourceGroupStore`. Ownership / sharing / admin transfer / backfill flow through the shared `OwnerStore` + `ShareStore` used by KV and Resources.

**Phase 5 (SMB) shipped** (`src/modules/files/smb.rs`, behind `files_smb` Cargo feature). `FileSyncTarget { kind = "smb" }` is now a valid sync target whose `target_path` is `smb://server[:port]/share/path/to/file` (or a backslash UNC `\\server\share\path`). NTLM auth via `smb_username` / `smb_password` / optional `smb_domain` fields on the target record (password barrier-encrypted at rest, redacted on read with a `smb_password_set` boolean surfaced instead). Atomic-ish push via tmp-then-rename in the same directory (matches the local-fs semantics). Driven by [`smolder-smb-core`](https://crates.io/crates/smolder-smb-core) — pure-Rust SMB2/3 + NTLM, no `libsmbclient` / `libsmb2` C dep, no Windows-only restriction. 9 unit tests (URL parser shapes, tmp-path same-directory invariant) + 2 new save-time validation assertions. Live-network integration tests against a Samba container are tracked as test infrastructure.

**Phase 6 (SFTP + SCP) shipped** (`src/modules/files/ssh_sync.rs`, behind `files_ssh_sync` Cargo feature). `FileSyncTarget { kind = "sftp" }` / `kind = "scp"` are now valid sync targets whose `target_path` is `sftp://[user@]host[:port]/path/to/file` / `scp://[user@]host[:port]/path/to/file`. SSH session built with [`russh`](https://crates.io/crates/russh) 0.45 (pure-Rust); SFTP uses [`russh-sftp`](https://crates.io/crates/russh-sftp) 2 over an SSH `sftp` subsystem channel; SCP uses an SSH exec channel running `scp -t <path>` with the OpenSSH SCP framing. Auth: inline `ssh_password` and/or `ssh_private_key` (with optional `ssh_passphrase`); key-then-password fallback. TOFU host-key handling with optional `ssh_host_key_fingerprint` pin in OpenSSH `SHA256:<base64>` format. Atomic-ish push via tmp-then-rename (SFTP's native `rename` for the SFTP transport; an exec-channel `mv` for SCP). 9 unit tests + 2 new save-time validation assertions. The `russh` dep tree pre-stages the planned Resource Connect SSH window. **Bootstrap-ordering decision**: credentials live inline on the target record (barrier-encrypted at rest) — the vault is already unsealed by the time a sync push runs, so there's no circular dependency on the vault to resolve a credential reference. Phase 7 (periodic re-sync) remains deferred.

**Phase 7 (periodic re-sync) deferred as a separate follow-up initiative.** Every file-resource feature works today against any combination of the local-FS / SMB / SFTP / SCP sync targets. See "Deferred sub-initiatives" below for scope.

Shipped in Phase 1 (`src/modules/files/mod.rs`):

- **Dedicated storage engine** mounted at `files/`, independent of the KV and resource engines. Storage layout inside the mount's barrier view: `meta/<id>` (FileEntry JSON), `blob/<id>` (raw content bytes), `hist/<id>/<nanos>` (change log).
- **Metadata + content CRUD** via a v2-accessible logical backend:
  - `POST files/files` — create a file, server assigns a UUID, returns `{id, size_bytes, sha256}`.
  - `LIST files/files` — list all file ids.
  - `GET files/files/{id}` — read metadata.
  - `GET files/files/{id}/content` — read content bytes (base64-wrapped in the JSON response).
  - `POST files/files/{id}` — replace content (and optionally metadata fields; omitted fields are preserved).
  - `DELETE files/files/{id}` — drop metadata + blob.
  - `GET files/files/{id}/history` — per-file change log (newest-first).
- **32 MiB hard cap** (`MAX_FILE_BYTES`) on content size, enforced server-side before any bytes are persisted.
- **SHA-256 over plaintext** stored in `FileEntry.sha256`. The content-read handler recomputes it and errors out on mismatch, so storage corruption or out-of-band writes produce a loud error instead of returning potentially-wrong bytes.
- **Change history** (who / when / op / changed_fields — never content bytes). Content replacement surfaces as `"content"` in `changed_fields` so the timeline reflects content movement even when no metadata changed.
- **Module wiring**: registered in `src/module_manager.rs`, default-mounted at `files/` in `src/mount.rs`, integrated with the standard barrier-encrypted storage path.
- **Tests** (12 in `src/modules/files/mod.rs`): size-cap rejection, SHA-256 determinism, content roundtrip, update-replaces-content with history entry carrying `"content"` in `changed_fields`, delete-then-read-returns-none, metadata-field diff logic, caller-username fallback chain.

Shipped in Phase 2 (this slice):

- **Owner tracking** in `OwnerStore`. New `owner/file/<id>` sub-view alongside the existing KV and resource owner stores. APIs: `get_file_owner`, `record_file_owner_if_absent`, `set_file_owner`, `forget_file_owner`. File IDs are UUIDs so no canonicalization is needed; the record key is the id itself.
- **Owner capture**: the files module's `handle_create` stamps `caller_audit_actor(req)` as the owner on every new file (root-token writes therefore stamp `"root"`, matching KV and resource behavior). `PolicyStore::post_route` also stamps on replace-by-id writes (`POST files/files/<id>`) so the old-and-new-author case is covered.
- **Owner forget + share-cascade** on delete: `PolicyStore::post_route` now forgets the file's owner record on `DELETE files/files/<id>` and cascade-revokes every `SecretShare` targeting that file. Failures log a warning but never fail the delete — consistent with the resource / KV paths.
- **`ShareTargetKind::File`** — new share-target variant (`"file"` wire string). `ShareStore::canonicalize` accepts any non-empty, slash-free id string. `shared_capabilities` on a file path is honored by the ACL evaluator (`scopes = ["shared"]` works for files).
- **Owner-aware ACL evaluation**: `resolve_asset_owner` and `resolve_target_shared_caps` in the policy evaluator now recognize `files/files/<id>` paths and return the corresponding owner / shared-capabilities from the store. `scopes = ["owner"]` rules on file paths now see the real owner; `scopes = ["shared"]` picks up explicit file shares.
- **`GET identity/owner/file/<id>`** — read the owner record for a file resource, same envelope as the existing `/owner/kv/<...>` and `/owner/resource/<...>` routes (the Sharing-tab GUI uses these for the Owner card).
- **`POST sys/file-owner/transfer`** — admin ownership-transfer endpoint (gated by the usual ACL on `sys/file-owner/transfer`, mirroring kv-owner / resource-owner / asset-group-owner transfer). Body: `{ id, new_owner_entity_id }`.
- **`sys/owner/backfill`** — extended with a `file_ids` field parallel to the existing `resources` and `kv_paths`. Response now includes a `files` summary (`stamped` / `already_owned` / `invalid`). One endpoint, three object kinds.
- **`looks_like_kv_path`** updated to exclude `files/`, so a file path never accidentally trips the KV owner-capture path.
- 5 new integration tests (17 total in the files module).

Shipped in this turn (asset-group files + Phases 3 + 4):

- **Asset-group file membership** — `ResourceGroupStore` gains a third reverse index (`resource-group/file-index/<id>`) parallel to the existing resource and secret indexes. `ResourceGroupEntry` carries a `files: Vec<String>` field; the write handler accepts a `files` comma-slice and canonicalizes ids the same way member names are canonicalized. `groups_for_file` + `prune_file` mirror the KV/resource versions and run on file DELETE from `PolicyStore::post_route`. `reindex` walks file entries. `resolve_asset_groups` now recognizes file paths so `groups = [...]` ACL rules on a file resolve to the caller's group membership.
- **Local-FS sync target** (`src/modules/files/mod.rs`):
  - New per-file sync-target storage (`sync/<id>/<name>`) and sync-state storage (`sync-state/<id>/<name>`). Both barrier-encrypted like everything else in the engine.
  - Routes: `GET files/{id}/sync` lists targets + per-target state; `POST|DELETE files/{id}/sync/{name}` create-or-replace / remove a target; `POST files/{id}/sync/{name}/push` performs an on-demand push.
  - Only `kind = "local-fs"` is accepted on save (other kinds reject with a clear error pointing at the later phase). Local-FS push creates parent directories, writes atomically via `<path>.bvsync.<pid>.tmp` + rename, and optionally applies a Unix mode after the write on Unix hosts. Windows hosts skip the mode step with a docstring note.
  - Failed pushes record `last_error` + `last_failure_at` on the sync-state **before** surfacing the error, so the GUI can display the reason on the next read.
  - Delete of a file drops all associated sync-target configs + sync-state records. Errors during the sweep are logged, not raised — the file delete already succeeded.
- **Tauri commands + TypeScript bindings** (`gui/src-tauri/src/commands/files.rs`, `gui/src/lib/api.ts`): `list_files`, `read_file_meta`, `read_file_content`, `create_file`, `update_file_content`, `delete_file`, `list_file_history`, `list_file_sync_targets`, `write_file_sync_target`, `delete_file_sync_target`, `push_file_sync_target`.
- **GUI Files page** (`gui/src/routes/FilesPage.tsx`): top-level nav entry; table of all files with Details / Download / Delete actions; upload modal with filename/resource/mime/notes; per-file detail modal with Info + Sync tabs; Sync tab supports add local-fs target, push, remove, and shows last-success / last-error timestamps per target. Confirm modal on delete with the "already-synced remote copies are not touched" disclaimer from the spec.

Shipped in this turn (Phase 8 — content versioning):

- **Per-file version index + historical blob storage** (`vmeta/<id>` + `vblob/<id>/<version>`). `FileVersionMeta` tracks `current_version` (monotonically incrementing) plus a retained `Vec<FileVersionInfo>` of prior snapshots (oldest first).
- **Snapshot-on-write.** `write_entry_and_blob` detects a content change (sha256 mismatch) and, *before* overwriting, reads the live blob + current metadata and records them as a new historical version. Metadata-only writes (same sha256) don't burn a version slot.
- **Retention with automatic prune.** `DEFAULT_VERSION_RETENTION = 5` — after appending a new snapshot, versions beyond the cap are dropped from the front of the list and the corresponding `vblob/<id>/<version>` key deleted. Set retention to `0` to disable snapshotting (existing records stay until the file is deleted).
- **Routes** (all under the existing `files/` mount):
  - `GET files/{id}/versions` — list retained versions + `current_version`.
  - `GET files/{id}/versions/{version}` — metadata for one historical version.
  - `GET files/{id}/versions/{version}/content` — base64 content of a historical version, with a SHA-256 re-verification on read that errors out loudly on mismatch.
  - `POST files/{id}/versions/{version}/restore` — swap a historical version into the live slot. The displaced content is itself snapshotted, so restore is reversible.
- **Delete cascade.** File DELETE now sweeps `vmeta/<id>` and every `vblob/<id>/*` alongside the existing sync-config + sync-state sweep. Failures are logged, not raised (the file delete already succeeded; a dangling version blob can never widen access because the owner + shares are gone).
- **Tauri commands** (`list_file_versions`, `read_file_version_content`, `restore_file_version`) + TypeScript bindings.
- **GUI**: new **Versions** tab on the file detail modal. Shows version number, size, short SHA-256, author, and when the version was displaced. Per-row Download and Restore actions. Restore goes through a confirm dialog with the "reversible" disclaimer.
- **Tests (3 new):** `test_file_versioning_snapshots_on_update` (two updates produce two versions with correct sha256s; v1 historical content round-trips; restore rolls the live content back to v1), `test_file_versioning_retention_prunes_oldest` (8 content writes with retention=5 ⇒ exactly 5 versions retained, oldest=v3), `test_file_delete_sweeps_versions` (vmeta + vblob cleared on file DELETE).

**Intentionally deferred** to later slices (in spec order):

- **Phase 5** — SMB sync target.
- **Phase 6** — SFTP / SCP sync targets.
- **Phase 7** — Periodic re-sync scheduler (today's `sync_on_write` flag is accepted and stored but not yet honored).
- Chunking for files above the inline 32 MiB cap.
- Operator-configurable retention (today hardcoded at 5).
- GUI polish: drag-and-drop upload zone, plain-text preview for small text files, tag chip editor.
- **Phase 4** — GUI.
- **Phases 5–6** — SMB, SCP, SFTP sync targets.
- **Phase 7** — Periodic re-sync scheduler.
- **Phase 8** — Multi-version content retention (today's writes overwrite; the history log still records the event).
- **Chunking** — the inline `blob/<id>` layout fits the 32 MiB cap comfortably. Chunking (`chunks/<id>/<seq>`) lands when the cap is raised or when streaming becomes necessary.

## Relationship to Resource Management

File Resources reuses the existing **Resources** framework (`src/modules/resource/`) rather than inventing a parallel one:

- A file belongs to a resource (a server, a network device, an application, etc.) the same way a secret does.
- The per-resource Files tab in the GUI sits alongside the existing Info / Secrets / History / Sharing tabs.
- Sharing, ownership, asset-group membership, audit trail — all reuse the identity layer already plumbed for resources and KV secrets.
- Standalone files (not attached to a resource) are supported via a top-level `files/` mount; the default is resource-attached because that's the common case.

## Data Model

### Storage Layout

New dedicated barrier-encrypted engine mounted at `files/`, mirroring the shape of `src/modules/resource/mod.rs`:

```
files/meta/<id>                        -> FileEntry JSON (metadata)
files/blob/<id>                        -> single-chunk payload (files <= 1 MiB)
files/chunks/<id>/<4-digit-seq>        -> payload chunks (files > 1 MiB)
files/hist/<id>/<20-digit-nanos>       -> change log (who + when + which fields)
files/sync/<id>/<target-name>          -> SyncTargetConfig JSON (where to sync)
files/sync-state/<id>/<target-name>    -> last-sync timestamp + content hash
```

Where `<id>` is a UUIDv7 so files sort by creation time in listings.

### FileEntry Metadata

```json
{
  "id": "018f3b2a-...-...-...-...",
  "name": "gateway-tls.pem",
  "resource": "primary-gateway",
  "mime_type": "application/x-pem-file",
  "size_bytes": 4827,
  "sha256": "hex...",
  "chunks": 1,
  "created_at": "2026-04-22T12:00:00Z",
  "updated_at": "2026-04-22T12:00:00Z",
  "tags": ["tls", "production"],
  "notes": "Wildcard cert for *.example.com, expires 2026-12-31"
}
```

### Size Limits

- Default hard cap: **32 MiB** per file. Configurable via `files.max_bytes` in server config.

  Operators who want to store files in a cloud account should use the [Cloud Storage Targets for `FileBackend`](cloud-storage-backend.md) feature — it makes the entire Encrypted File backend (including File Resource content) write its barrier-encrypted bytes to S3 / OneDrive / Google Drive / Dropbox, lifting the practical size constraints imposed by local-disk / MySQL row size / Hiqlite BLOB limits.
- Files > 1 MiB are split into 1 MiB chunks (`files/chunks/<id>/0001`, `0002`, …). Each chunk passes through the barrier independently; AEAD authenticates each chunk.
- A manifest-level SHA-256 over the *plaintext* is stored in metadata so the caller can verify whole-file integrity after reassembly.
- Chunking is transparent to callers — the API accepts and returns the whole file; chunking lives inside the engine.

Why the cap: physical backends (MySQL row size, Hiqlite SQLite BLOB, Raft log entry size) have practical limits. 32 MiB keeps a single object well under those limits even when chunked, and discourages storing artifacts that belong in an object store or artifact registry. Operators who need larger can raise the cap explicitly.

## API

### HTTP routes (under `v2/`)

| Method | Path | Description |
|--------|------|-------------|
| POST   | `v2/files` | Create a new file. Body: multipart form (`name`, `resource?`, `mime_type?`, `content`) or JSON (`content_base64`). Returns `id`. |
| GET    | `v2/files` | List files, optionally filtered by `resource=...` or `tag=...`. Returns metadata only. |
| GET    | `v2/files/{id}` | Read file metadata. |
| GET    | `v2/files/{id}/content` | Stream file content. Sets `Content-Type` from metadata, `Content-Disposition: attachment; filename=...`. |
| PUT    | `v2/files/{id}` | Replace content (creates a new version; old chunks kept until version retention expires). |
| PATCH  | `v2/files/{id}` | Update metadata fields (`name`, `tags`, `notes`) without replacing content. |
| DELETE | `v2/files/{id}` | Delete the file, all versions, all chunks, and cascade any shares. |
| GET    | `v2/files/{id}/history` | Change log (metadata updates only — content hashes in the log, never bytes). |

Per-v2-routing rule, all new routes land on `v2/` and there is no `v1/` equivalent.

### Tauri commands

Mirror the HTTP routes: `list_files`, `read_file_meta`, `read_file_content`, `create_file`, `update_file_content`, `update_file_meta`, `delete_file`, `list_file_history`.

## Sync Targets

A **sync target** is a description of *where else* this file should live. Each file can have zero or more sync targets. The vault is always the source of truth; sync targets are secondary copies.

### Supported backends (phased)

| Backend | Auth | Phase |
|---------|------|-------|
| Local filesystem (path on the vault host) | Filesystem permissions | Phase 3 |
| SMB (CIFS) share | NTLM / Kerberos | Phase 5 |
| SFTP | SSH key (private key stored as a file resource itself) or password | Phase 6 |
| SCP | Same as SFTP | Phase 6 |

SMB, SFTP, and SCP all have mature Rust crates (`rsmb-rs`/`smb-rs`, `russh`/`russh-sftp`). Picking a crate per transport lands in the per-phase scoping doc, not here.

### Sync semantics

- **Push only** in v1. The vault is authoritative; sync writes the current vault content to the target path on every sync. No conflict resolution, no read-back.
- **Triggers**:
  - On-demand: `POST v2/files/{id}/sync/{target}` forces an immediate sync.
  - On-write: configurable per-target flag `sync_on_write = true` pushes whenever the file content changes.
  - Periodic: a cluster-wide `files_sync_interval` (default off) re-pushes all sync-enabled files every N minutes, in case a target's local copy drifts.
- **Failure handling**: sync failures are logged to the audit trail and surfaced in the GUI's per-file Sync tab. Failures do **not** fail the underlying vault write. The `files/sync-state/{id}/{target}` record holds last-success-at, last-failure-at, last-error.
- **Bidirectional sync (pull-from-target) is out of scope** for the first ship. It requires conflict resolution (vault vs. target both modified) and operator intent signalling that's not obvious from a UI. Revisit after v1 is in production use.

### Credentials

Sync-target credentials (SSH keys, SMB passwords) are themselves stored in the vault — a sync target references a KV secret or another file resource for its credentials by path. Example SFTP target config:

```json
{
  "kind": "sftp",
  "host": "deploy-01.example.com",
  "port": 22,
  "remote_path": "/etc/ssl/private/gateway.pem",
  "auth": {
    "kind": "ssh_key",
    "key_file_id": "018f-.-of-another-file-resource-.-holding-the-key"
  },
  "sync_on_write": true,
  "mode": "0600",
  "owner": "root",
  "group": "root"
}
```

This keeps secrets where they belong (the vault) and avoids a new credential silo just for sync. The reference is a file-resource id, not a filesystem path, so the SSH key itself is encrypted at rest under the barrier.

## Security Considerations

- **Content-at-rest**: every chunk goes through the existing barrier AEAD. Confidentiality + integrity inherit from the policy.
- **Memory footprint**: reading a large file decrypts chunks sequentially and streams to the caller. The whole plaintext never needs to sit in memory at once. Same for writes.
- **Audit**: the history log records who added / replaced / deleted a file and which metadata fields changed, never the content bytes or their hash-of-hashes. Content hashes go into `FileEntry.sha256` and the immutable sync-state record, both of which are available only to authorized readers.
- **Sync-target credentials are themselves secrets**. Referencing them by vault-id rather than inlining the SSH key in the sync config keeps the normal ownership + sharing controls applicable — a user who shouldn't be able to read the SSH key shouldn't be able to extract it by reading a sync config either.
- **Sync-target trust boundary**: pushing a file to SCP/SFTP/SMB exposes the plaintext to whatever account the sync runs as, on whatever host. Operators opting into sync accept that the target host is trusted with the content. The GUI's per-target add-dialog states this explicitly before saving.
- **No plaintext leaks via logs**: sync failures log transport errors (connection refused, auth failed, disk full) and target paths, never content.
- **Size caps** prevent a malicious caller from exhausting disk by uploading many huge files (a secret-storage system is not a swap partition).

## GUI

### New pages + tabs

- **Resources detail → Files tab** — list files attached to this resource. Upload / download / rename / delete / configure sync. Plain-text preview for files under 64 KiB with a text-ish MIME type.
- **Files page** (top-level nav, under Resources) — global list of every file the caller can see, grouped by resource, with tag and name filters.
- **Per-file detail** — metadata + Sync tab (list of targets, last-sync timestamps, manual re-sync button) + History + Sharing.

### Upload UX

- Drag-and-drop + "Choose file". Client-side size check against the server-reported `files.max_bytes`. Show MIME type detection result before submitting; operator can override.

## Configuration

```hcl
files {
  max_bytes              = 33554432   # 32 MiB, default
  chunk_bytes            = 1048576    # 1 MiB, default
  files_sync_interval    = "0s"       # 0s = no periodic sync
  sync_concurrency       = 4          # max parallel sync jobs per target kind
}
```

## Phases

| # | Phase | Scope |
|---|-------|-------|
| 1 | Engine scaffold | `src/modules/files/` module, barrier-encrypted storage layout, chunking, metadata CRUD, `v2/files` HTTP surface. 32 MiB cap enforced server-side. |
| 2 | Integration | Ownership + sharing + asset-group wiring through the identity layer (mirror what resources did). Audit events for file-create/update/delete. |
| 3 | Local-filesystem sync target | First sync backend (writes to a path on the vault host). Push-only. On-demand + on-write triggers. Per-target state + audit. |
| 4 | GUI | Resources-detail Files tab + top-level Files page + per-file detail. Plain-text preview. Drag-and-drop upload. Sync-target management UI with the "target is trusted" confirmation. |
| 5 | SMB sync target | NTLM + Kerberos auth. Credential reference into vault. |
| 6 | SFTP + SCP sync targets | SSH-key auth (with the key itself stored as a file resource), password auth. |
| 7 | Periodic re-sync | Cluster-wide scheduler. Detect sync-state drift. |
| 8 | Versioning + retention | Keep N previous content versions per file; GC on delete. Mirrors the per-secret version log the resource engine already has. |

Phase 1 is the critical path. Phases 5–6 are parallelizable after Phase 3 proves the sync abstraction.

## Testing Requirements

- **Unit**: chunk-split / chunk-reassemble round-trip across the barrier. Size-cap rejection. Metadata CRUD. History log entries. Stream-style large-file read without whole-buffer allocation.
- **Integration**: upload → read back byte-for-byte; replace content → old chunks GC'd; delete → cascade to shares + sync configs + chunks.
- **Sync (local FS)**: push succeeds; target permissions match config; target-path-missing creates directories; target-write-failure surfaces in sync-state and does not fail the vault write.
- **Sync (SMB / SFTP / SCP)**: against local test daemons in CI (Samba container, OpenSSH container). Record-and-replay fixtures for auth failure / connection refused / disk full.
- **Security regression**: audit logs never contain content bytes; memory dump during a large-file read shows decrypted plaintext only for the currently-streaming chunk, not the whole file.
- **Compatibility**: a vault migrated across storage backends (via `operator migrate`) preserves every file bit-for-bit including chunk ordering.

## Operational Safety Notes

- Marked **Experimental** in the GUI until Phase 2's test suite is green.
- The GUI warns on first sync-target add that the target host is trusted with the plaintext content.
- Deleting a file cascades to its shares and sync configs but *not* to previously-synced copies on remote hosts — operators must clean those up explicitly. This is called out in both the DELETE confirmation and the audit row.
- Audit events emit `files.create`, `files.update.content`, `files.update.meta`, `files.delete`, `files.sync.success`, `files.sync.failure` so operators can track file-handling separately from secret-handling.

## Deferred sub-initiatives

Three sync-related phases did not land in the core File Resources
initiative. Each is self-contained and would warrant its own
focused session with its own dep decision and test infrastructure.
None of them is required for the core feature — operators who
need file replication today use the Phase-3 local-FS target (often
pointed at a mount managed out-of-band by `rclone`, `rsync`,
`syncthing`, etc.) until an in-tree transport ships.

### SMB sync target (was Phase 5)

**Scope.** A `FileSyncTarget { kind = "smb", target_path = "//host/share/path", credentials_ref, ... }` that pushes the current file content to an SMB share.

**Blocking questions for a future session:**
- Crate choice. `pavao` (pure Rust, SMB2/3) and `smb3` are the main options; both are alpha/beta and should be evaluated head-to-head against a Samba server before being baked into `Cargo.toml`.
- Auth. NTLM is table stakes; Kerberos/AD is where the complexity lives. First cut can be NTLMv2 only.
- Windows-native vs. portable. Windows has first-class SMB client APIs via `windows-rs`; Linux + macOS need a pure-Rust crate. Either maintain two impls or pick one pure-Rust path and live with the quality trade-off on Windows.

**Test infrastructure.** Samba container in CI (`docker run -p 445 ghcr.io/servercontainers/samba`), fixture for successful push, auth failure, and disk-full.

### SFTP + SCP sync targets (was Phase 6)

**Scope.** Two transports sharing an SSH session: `kind = "sftp"` and `kind = "scp"`. Auth via SSH private key (where the key itself can be a file resource stored in the vault) or password.

**Blocking questions:**
- Crate choice. `russh` + `russh-sftp` (pure Rust, maintained) is the lead option; `libssh2-sys` is the C-library alternative. Prefer `russh` unless interop testing reveals protocol-edge-case gaps.
- Key management. The "SSH key lives in the vault" case creates a bootstrap ordering concern: the file resource containing the key has to be readable before sync can push — so the sync engine needs to resolve the key out of its own vault at push time, not at target-config time.

**Test infrastructure.** OpenSSH container in CI; fixture for pubkey-auth push, password-auth push, host-key-mismatch rejection, bad-credential rejection.

### Periodic re-sync (was Phase 7)

**Scope.** Most sync targets today push on first write and on manual `POST files/{id}/sync/{name}/push`. A periodic re-sync would also push stale copies in the background — useful for a fleet where multiple hosts hold synced copies and the vault wants to guarantee they converge.

**Design question.** Two viable shapes:
- **Internal scheduler.** Background tokio task started at post-unseal, stopped at pre-seal. Touches the vault lifecycle. Sharper single-host story.
- **External-tick endpoint.** `POST sys/files/sync/tick` that the operator wires into cron / systemd / k8s CronJob. Simpler, no lifecycle concerns, defers HA coordination to the scheduler the operator already runs.

**Cluster coordination.** With Hiqlite storage the re-sync task must run on exactly one node at a time; `hiqlite::dlock` is the existing primitive for that.

**Blocked on** the SMB or SFTP sync targets landing first — with only local-FS there's nothing to re-sync that the filesystem itself doesn't already handle.
