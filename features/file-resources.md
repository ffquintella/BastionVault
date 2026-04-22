# Feature: File Resources

## Summary

A new resource kind that stores **files** — arbitrary binary blobs with filename, MIME type, size, and integrity metadata — under the vault barrier alongside secrets. Files inherit the existing per-user-scoping model (ownership, sharing, ACLs, audit). Phase 1 stores files locally in the vault backend the same way KV secrets do. Later phases add **SMB**, **SCP**, and **SFTP** sync targets so the vault can mirror file content out to (or import from) a network share.

## Status

**Todo — design only.** Nothing implemented yet. This document captures the intended design so it can be reviewed before code lands.

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

Not started. This feature file exists to scope the work before implementation begins.

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
