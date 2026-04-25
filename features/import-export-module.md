# Feature: Import / Export Module (User-Facing JSON, Optional Password-Encrypted)

## Summary

Add a **user-facing import / export module** that lets operators and end-users round-trip vault data as a portable, human-readable **JSON** document, with an **optional password-encrypted variant** (`.bvx` — *BastionVault Exchange*) for safe transmission outside the vault. The module sits on top of the existing backup/export plumbing ([features/import-export-backup-restore.md](import-export-backup-restore.md)) but targets a fundamentally different use case: **moving secrets between people, machines, and vault instances** without going through a full BVBK backup-restore cycle.

The design ships in three layers:

1. **JSON schema (`bvx.v1`)** — a stable, versioned, human-readable JSON document describing a selected subset of vault data: KV items, resources, file-resource metadata + payload (base64), asset / resource-group memberships, and (opt-in) policies + identity entities.
2. **Password-encryption envelope (`.bvx`)** — Argon2id (memory-hard) KDF → 256-bit key → XChaCha20-Poly1305 AEAD over the canonical JSON bytes, with embedded KDF parameters so future tuning is forward-compatible.
3. **Conflict-aware import flow** — parse, decrypt, dry-run preview (counts + per-item conflict listing), then apply with a per-item or global `skip / overwrite / rename` policy.

Both layers are exposed via the **HTTP API** (`/v1/sys/exchange/*`), the **CLI** (`bvault exchange export / import`), and a new **GUI page** (`/exchange`).

## Motivation

- **Today's tooling solves the wrong problem.** The shipped Import/Export & Backup/Restore feature ([features/import-export-backup-restore.md](import-export-backup-restore.md)) targets *operators*: BVBK is a binary archive HMAC'd with the vault's audit-device key, and the existing JSON export is **decrypted plaintext** with no integrity / no encryption / no schema versioning. Neither is suitable for the day-to-day "Alice needs to hand Bob these 12 secrets" workflow that customers ask for repeatedly.
- **Password-encrypted exchange is the realistic threat model.** When secrets cross machine or org boundaries, the recipient typically does **not** share Alice's vault. They have a password (or a passphrase, or a TOTP-derived value, or a phone call) — not a vault token, not the audit HMAC key. A password-encrypted file, decrypted on the recipient's BastionVault, is the workflow that actually happens.
- **Versioned JSON unblocks third-party tooling.** A schema version + JSON Schema definition lets GRC tools, migration scripts, and CI pipelines parse exports without reverse-engineering binary formats. The existing BVBK is intentionally opaque; a `bvx.v1` JSON document is intentionally inspectable.
- **Selective scope is non-negotiable for usability.** The full-vault BVBK is the right primitive for disaster recovery; it is the wrong primitive for "share these 12 secrets." A per-mount / per-path-prefix / per-resource-group / per-asset-group / per-share scope is what users actually pick from a GUI dropdown.
- **Imports need a preview.** "Click button, file overwrites 800 secrets, can't undo" is unacceptable. A dry-run preview that shows counts + conflicts before any write happens is the entire point of having a separate import flow.

## Current State

- **Existing infrastructure already shipped** ([features/import-export-backup-restore.md](import-export-backup-restore.md)):
  - `src/backup/format.rs` — BVBK binary format with HMAC-SHA256.
  - `src/backup/create.rs` / `restore.rs` — full-vault encrypted backup/restore.
  - `src/backup/export.rs` / `import.rs` — *decrypted* JSON export per-mount; import with `--force`.
  - CLI: `bvault operator backup/restore/export/import`.
  - HTTP: `POST /v1/sys/backup`, `POST /v1/sys/restore`, `GET /v1/sys/export/{path}`, `POST /v1/sys/import/{mount}`.
- **What's missing for the new feature:**
  - No password-based key derivation in the tree (no `argon2` / `pbkdf2` dep).
  - No stable, versioned, human-readable JSON schema. The existing export is a mount-specific snapshot, not a portable document.
  - No conflict-aware import (the existing import is `--force`-only).
  - No GUI for selective export / preview-before-import.
  - No way to include resources + file metadata + group memberships + policies + identities in a single document — the existing export is per-mount.
- **Pure-Rust crypto stack already covers the AEAD half.** XChaCha20-Poly1305 lives in `bv_crypto::aead`; the new feature only needs to add the KDF layer.

## Design

### File Format: `bvx.v1`

Two on-disk variants share the same JSON schema:

- `*.json` — plaintext canonical JSON. Convenient for diffing, GRC tooling, and automation pipelines that already operate inside trusted boundaries. Refused by the import endpoint unless the operator explicitly passes `--allow-plaintext` (or sets `accept_plaintext_exchange = true` on the engine config). The default is *encrypted*, even when the data is small or seemingly low-sensitivity, to avoid the foot-gun where someone exports `secret/dev/...` thinking it's safe and the file ends up in Slack.
- `*.bvx` — password-encrypted envelope. The default and recommended form.

### `.bvx` Envelope Layout

The envelope is **itself** a small JSON document so it is self-describing and easy to inspect before decryption:

```json
{
  "magic": "BVX",
  "version": 1,
  "kdf": {
    "alg": "argon2id",
    "version": 19,
    "m_cost_kib": 65536,
    "t_cost": 3,
    "p_cost": 1,
    "salt_b64": "<base64 16 bytes>"
  },
  "aead": {
    "alg": "xchacha20-poly1305",
    "nonce_b64": "<base64 24 bytes>"
  },
  "ciphertext_b64": "<base64 of (AEAD-encrypted canonical bvx.v1 JSON || tag)>",
  "created_at": "2026-04-25T18:00:00Z",
  "vault_fingerprint_b64": "<base64 BLAKE2b-256(vault_root_pubkey)>",
  "comment": "optional operator-set string, max 256 chars"
}
```

Notes:
- **The envelope JSON itself is not authenticated by the password.** Tampering with the envelope (e.g. swapping the salt) makes the AEAD decryption fail closed; this is what we want — the recipient learns "the password didn't decrypt this" rather than reading attacker-controlled data.
- The `vault_fingerprint_b64` lets the importer warn when re-importing a file produced by a *different* vault (e.g. moving from staging to prod) so the user is asked to confirm.
- KDF parameters are embedded so we can raise defaults later (e.g. `m_cost_kib = 131072` in 2027) without breaking files exported under the old defaults.

### Inner Document: `bvx.v1` JSON Schema

The cleartext JSON the AEAD wraps:

```json
{
  "schema": "bvx.v1",
  "exported_at": "2026-04-25T18:00:00Z",
  "exporter": {
    "vault_fingerprint_b64": "...",
    "namespace": "engineering/platform",
    "actor": { "entity_id": "...", "display_name": "alice" }
  },
  "scope": {
    "kind": "selective",
    "include": [
      { "type": "kv_path",         "mount": "secret/", "path": "myapp/" },
      { "type": "resource",        "id": "uuid-..." },
      { "type": "asset_group",     "id": "uuid-..." },
      { "type": "resource_group",  "id": "uuid-..." }
    ]
  },
  "items": {
    "kv": [
      {
        "mount": "secret/",
        "path": "myapp/db",
        "version": 7,
        "data": { "password": "...", "username": "..." },
        "metadata": { "created_at": "...", "owner_entity_id": "..." }
      }
    ],
    "resources": [
      { "id": "...", "type_id": "server", "name": "t12", "fields": {...}, "owner_entity_id": "..." }
    ],
    "files": [
      {
        "id": "...",
        "name": "ca.crt",
        "size": 4321,
        "sha256": "...",
        "content_b64": "...",
        "metadata": {...}
      }
    ],
    "asset_groups": [ ... ],
    "resource_groups": [ ... ]
  },
  "optional": {
    "policies":  [ ... ],
    "entities":  [ ... ],
    "groups":    [ ... ]
  },
  "warnings": [
    "Excluded 3 secrets the actor lacked read on"
  ]
}
```

Key decisions:
- **Canonical JSON**: keys sorted, LF line endings, no trailing whitespace. Two exports of the same scope at the same instant produce byte-identical JSON. This is what makes the AEAD authentication meaningful — a tampered field flips the tag.
- **Owner / sharing / metadata is preserved** so a re-import recreates the per-user-scoping state rather than losing it.
- **`optional`** is opt-in (`--include-policies`, `--include-identity`). Default exports do **not** include policies or identity, because most real-world workflows are "share these specific secrets" and bundling identity is over-scope.
- **Warnings are part of the document** so the recipient sees "you got 12 of 15 items the exporter intended; the other 3 were silently filtered by ACL" without having to chase logs.

### Password-Based Key Derivation

- **Argon2id** (RustCrypto `argon2` crate, pure Rust). KDF parameters embedded in the envelope.
- **Defaults**: `m_cost_kib = 65536` (64 MiB), `t_cost = 3`, `p_cost = 1`. These match OWASP's 2024 cheat-sheet recommendation and target ~1 second on a modern desktop.
- **Salt**: 16 random bytes from `OsRng`.
- **Output**: 32 bytes → XChaCha20-Poly1305 key.
- **Nonce**: 24 random bytes from `OsRng` (XChaCha20 has a 192-bit nonce, so collisions are not a concern even across millions of exports).

### Password Strength

- The HTTP and CLI endpoints **enforce** a minimum password length (12 characters by default; configurable per-mount via `min_export_password_length`). This is a floor, not a ceiling — operators can tune higher for sensitive deployments.
- The GUI shows a **live entropy estimate** using a small zxcvbn-style Rust crate (`zxcvbn`) — purely client-side, no password ever leaves the browser before encryption.
- We deliberately **do not** offer a "passwordless" mode. If the operator wants un-encrypted export, they must use the explicit plaintext JSON variant (which is also auditable as a separate event type), so the cryptographic and policy decisions are surfaced rather than hidden.

### Scope Resolution

The exporter resolves a `scope` block into a set of items, applying ACL **at the scope level**, not just at the file level:

- Every item the actor lacks `read` on is silently dropped, *and* the count is recorded in the document's `warnings` field.
- Every dependency required to make the export self-consistent is auto-added unless `--strict-scope`:
  - A KV path drags in its mount config (the metadata, not other paths).
  - A resource drags in its file resources (if any) and its asset-group memberships (membership rows only — not the other members of the group, unless those members are also in scope).
  - An asset-group drags in its members iff the actor has read on each.
- The resolver returns a deterministic ordering (mounts → resources → asset-groups → resource-groups → files), so two exports of the same scope produce byte-identical inner JSON.

### Import Flow (Two-Step, Always)

`POST /v1/sys/exchange/import/preview`:

1. Accept the file (`.bvx` or `.json`) + optional password.
2. Decrypt if `.bvx`; otherwise refuse unless `--allow-plaintext`.
3. Parse + validate the schema.
4. For every item, classify against the destination vault:
   - **new**: target path/id does not exist → would be created.
   - **identical**: target exists with byte-identical bytes → no-op.
   - **conflict**: target exists with different bytes → import would overwrite, skip, or rename based on policy.
   - **forbidden**: actor lacks `write` on the target → cannot be imported.
5. Return a preview document (same schema as the export, plus per-item classification + a per-scope summary `{ new, identical, conflict, forbidden }`).

`POST /v1/sys/exchange/import/apply`:

1. Accept the preview's opaque `preview_token` (single-use, expires in 10 minutes), the password (re-supplied — the preview does not retain it), and a per-item or global conflict policy:
   - `skip`: keep the existing version.
   - `overwrite`: replace.
   - `rename`: write the imported version under `<path>.imported.<timestamp>` (KV) or `<name> (imported)` (resources).
2. Apply each item under a transactional batch (per the existing batch-operations primitive).
3. Emit one audit event per item.
4. Return the final summary `{ applied, skipped, renamed, errored }`.

The preview-then-apply split is mandatory; there is no single-shot import. This is the price we pay for "no surprise overwrites."

### CLI Surface

```
bvault exchange export   --scope kv:secret/myapp/ --scope resource:<uuid> \
                         --output myapp.bvx                              \
                         --password-stdin                                # or --no-encryption (refused unless --allow-plaintext)

bvault exchange preview  --input myapp.bvx --password-stdin

bvault exchange import   --input myapp.bvx --password-stdin              \
                         --conflict overwrite                            # or skip / rename
```

Passwords are **never** taken from a flag (`--password=foo`) — only from stdin or a TTY prompt. The CLI refuses the password flag with an error pointing at the safer alternatives.

### HTTP Surface

```
POST   /v1/sys/exchange/export                # body: { scope, password, format, options }
POST   /v1/sys/exchange/import/preview        # multipart: file + password
POST   /v1/sys/exchange/import/apply          # body: { preview_token, password, conflict_policy }
GET    /v1/sys/exchange/preview/<token>       # re-fetch a previously generated preview
DELETE /v1/sys/exchange/preview/<token>       # explicit cancel; storage cleanup
```

`exchange/export` returns the bytes of the `.bvx` (or `.json`) directly with `Content-Type: application/octet-stream` (binary `.bvx`) or `application/json` (plaintext export). For very large exports, the response is streamed.

### GUI

A new top-level page `/exchange` (visible to all authenticated users; per-item ACL governs what they can actually export):

- **Export tab**:
  - Scope picker — tree view of mounts / paths / resources / asset-groups / resource-groups, each with a checkbox.
  - Password input + entropy meter (zxcvbn).
  - "Include optional sections" toggles (policies, identities). Off by default.
  - Preview button → shows "X items, Y warnings" before download.
  - Download button.
- **Import tab**:
  - File picker (drag-and-drop accepted for both `.bvx` and `.json`).
  - Password input.
  - "Decrypt & Preview" button → renders the preview classification table.
  - Per-item conflict-policy override; bulk-set buttons (Skip all / Overwrite all / Rename all).
  - "Apply Import" button → final confirm dialog with the summary counts.
  - Result panel with the applied / skipped / renamed / errored counts and a link to the audit page filtered to this batch.

### Module Architecture

```
src/modules/exchange/
├── mod.rs                          -- ExchangeModule; sys path registration
├── format/
│   ├── mod.rs                      -- top-level exporter/importer
│   ├── envelope.rs                 -- .bvx envelope encode/decode (KDF + AEAD)
│   ├── schema_v1.rs                -- bvx.v1 JSON struct + serde
│   └── canonical.rs                -- canonical JSON encoder (key sort, LF, no whitespace)
├── kdf.rs                          -- Argon2id wrapper + parameter validation
├── scope.rs                        -- scope resolver: scope spec -> Vec<Item>
├── classify.rs                     -- diff incoming items against destination vault
├── preview.rs                      -- preview store (token-keyed, TTL'd)
├── apply.rs                        -- transactional batch importer
├── audit.rs                        -- exchange_export / exchange_import event emitters
└── path_*.rs                       -- /v1/sys/exchange/* HTTP handlers
```

Plus CLI: `src/cli/command/exchange_*.rs`. Plus GUI: `gui/src/routes/ExchangePage.tsx`, `gui/src/components/ExchangeScopePicker.tsx`, `gui/src/components/ExchangePreviewTable.tsx`.

### Audit Schema

Two new event types, joining the existing audit pipeline:

- `exchange_export` — `{ actor, namespace, scope, item_count, encrypted: bool, vault_fingerprint, comment }`. Does **not** log the password (or any derivative).
- `exchange_import` — `{ actor, namespace, scope, applied, skipped, renamed, errored, source_vault_fingerprint, conflict_policy }`. Each individual write also generates the standard `secret_write` / `resource_write` / etc. event so existing audit reports include the imported items.

### Interplay with Existing Features

- **Per-user scoping** ([features/per-user-scoping.md](per-user-scoping.md)): exports preserve owner / shared-with metadata. On import, owner defaults to the importing actor unless they have admin-transfer permission and explicitly pass `--preserve-ownership`.
- **Asset / resource groups**: group membership is preserved when both the group and the member are in scope; otherwise dropped with a warning.
- **File resources**: payload is base64-encoded inline. A 32 MiB hard cap (matching the existing file-resource limit) applies per file. For exports that would exceed 1 GiB total, the export is refused with a pointer to the BVBK backup primitive.
- **Compliance Reporting** ([features/compliance-reporting.md](compliance-reporting.md)): exchange events appear under SOC 2 CC8.1 (change-management) and ISO A.5.18 (access management) reports automatically — no special-case wiring.
- **Namespaces** ([features/namespaces-multitenancy.md](namespaces-multitenancy.md)): exports are namespace-scoped. Cross-namespace export requires the actor to hold `child_visible=true` in the target chain. Imports never cross a namespace boundary; the `bvx.v1` document records the namespace at export time and the importer refuses to write into a different namespace unless `--allow-namespace-rewrite` is set.

## Implementation Scope

### Phase 1 — Plaintext JSON Round-Trip + Scope Resolver

| File | Purpose |
|---|---|
| `src/modules/exchange/mod.rs` | Module + route registration. |
| `src/modules/exchange/format/{mod,schema_v1,canonical}.rs` | bvx.v1 schema + canonical encoder. |
| `src/modules/exchange/scope.rs` | Scope resolver. |
| `src/modules/exchange/classify.rs` | Incoming-vs-destination diff. |
| `src/modules/exchange/preview.rs` + `apply.rs` | Two-step import flow. |
| `src/modules/exchange/path_*.rs` | HTTP handlers. |
| `src/cli/command/exchange_*.rs` | CLI commands (without password support yet). |

### Phase 2 — Password-Encrypted `.bvx` Envelope

| File | Purpose |
|---|---|
| `src/modules/exchange/format/envelope.rs` | `.bvx` encode / decode. |
| `src/modules/exchange/kdf.rs` | Argon2id wrapper. |

Dependencies:

```toml
argon2  = { version = "0.5", default-features = false, features = ["alloc", "std"] }
zeroize = { version = "1.8", features = ["derive"] }    # already transitive; explicit to make password handling intentional
```

(`xchacha20poly1305` is already available via `bv_crypto::aead`.)

### Phase 3 — GUI Integration

| File | Purpose |
|---|---|
| `gui/src/routes/ExchangePage.tsx` | Top-level page with Export / Import tabs. |
| `gui/src/components/ExchangeScopePicker.tsx` | Tree-checkbox scope picker. |
| `gui/src/components/ExchangePreviewTable.tsx` | Per-item conflict-policy table. |
| `gui/src/lib/zxcvbn.ts` | Password entropy meter glue. |
| `gui/src/lib/api.ts` (extension) | `exchangeExport` / `exchangePreview` / `exchangeApply` typed wrappers. |

Dependencies (GUI):

```json
"@zxcvbn-ts/core":            "^3"
"@zxcvbn-ts/language-common": "^3"
"@zxcvbn-ts/language-en":     "^3"
```

### Phase 4 — Selective Export Polish + File Resource Inlining

| File | Purpose |
|---|---|
| `src/modules/exchange/scope.rs` (extension) | Asset-group / resource-group expansion + dependency drag-in. |
| `src/modules/exchange/format/schema_v1.rs` (extension) | File-payload base64 inlining + 32 MiB / 1 GiB caps. |

### Not In Scope

- **Diff-based incremental exports.** Each export is a full snapshot of its scope. Incremental syncs belong to the cloud-target sync infrastructure ([features/cloud-storage-backend.md](cloud-storage-backend.md)) or to dynamic-secrets, not here.
- **Public-key-based exchange (encrypt-to-recipient instead of password).** A reasonable v2 — pair with the planned PKI / Transit ML-KEM-768 work. For v1, password-based exchange is the simplest workflow that doesn't require pre-shared infrastructure.
- **Cross-version migrations.** The schema is versioned; major-version bumps will ship migration tooling at that time, but v1 is the baseline.
- **Streaming / chunked AEAD for >1 GiB exports.** Files of that size should use BVBK + cloud-storage sync, not exchange. The exchange flow is for human-scale subsets.
- **In-place re-encryption to a new password.** A user who wants to rotate the password on an existing file decrypts and re-exports.
- **GPG / age compatibility.** We considered piggy-backing on age's encrypted-file format; the additional dependency surface and the loss of the inspectable JSON envelope outweighed the interop benefit. Operators who want age can pipe the plaintext export through `age` themselves.

## Testing Requirements

### Unit Tests

- Canonical JSON encoder: same Rust struct → byte-identical output across two runs and across platforms (we explicitly do not use `std::collections::HashMap` for any nested object — all maps are sorted `BTreeMap`s).
- Argon2id wrapper round-trip with the documented defaults; refuses parameters below a sanity floor (`m_cost_kib < 16384`, `t_cost < 2`).
- `.bvx` envelope: encode → decode round-trip with the right password produces identical bytes; wrong password fails closed with `decryption_failed`; tampered ciphertext fails closed; tampered envelope outer fields fail closed (because the AEAD-AD or the recomputed key would differ).
- Scope resolver: every documented scope kind (`kv_path`, `resource`, `asset_group`, `resource_group`) resolves; ACL filtering produces the right warning counts.
- Classifier: every classification (`new`, `identical`, `conflict`, `forbidden`) reachable on synthetic fixtures.
- Preview store: token-keyed, single-use on apply, expires after 10 minutes.

### Integration Tests

- Round-trip a 50-secret export from vault A to vault B; confirm imported secrets read back identical including owner metadata.
- Round-trip the same with file resources inlined; confirm SHA-256 matches both before and after import.
- Multi-namespace export: actor without `child_visible=true` is refused at scope time; with it, the export succeeds and the importer rejects writing into a different namespace without `--allow-namespace-rewrite`.
- Conflict-resolution: import where 5 paths exist with different bytes; classify shows 5 `conflict`; apply with `rename` produces 5 new paths suffixed `.imported.<timestamp>`; original 5 unchanged.
- Audit chain: every export and import event lands in the audit log; rerunning Compliance Reporting CC8.1 picks them up under change-management.

### Cucumber BDD Scenarios

- Alice exports `secret/myapp/*` to a `.bvx` with a 16-character password and emails the file to Bob; Bob imports against a fresh vault; previews the 12 items as `new`; applies; reads back the secrets identical.
- Bob enters the wrong password on Alice's file; the GUI returns a decryption-failed error without revealing whether the file is well-formed.
- Carol exports a single resource that drags in three file resources via dependency-drag-in; the recipient sees all four items in the preview.
- Operator attempts a plaintext JSON export with the engine's `accept_plaintext_exchange = false`; refused with a pointer at the password-encrypted variant.

### Negative Tests

- `--password=foo` on the CLI: refused with an explanation of the safer alternatives.
- Password shorter than `min_export_password_length`: refused at export time, before any KDF work runs.
- Importing a `.bvx` whose `version` is higher than the host supports: refused with the supported version range.
- Importing a `.bvx` whose `vault_fingerprint_b64` doesn't match any vault the importer is signed in to: warned (not refused) — the operator must explicitly confirm.
- Apply token reused: refused with `preview_already_consumed`.
- Apply token from another actor: refused with `preview_owner_mismatch`.

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`**: same constraint as every other module. CI must fail if either becomes reachable. `argon2` and `xchacha20poly1305` are pure Rust.
- **Passwords never persist.** The HTTP path takes the password in the request body, derives the key, encrypts/decrypts, zeroises both the password and the derived key, and discards them. The audit event records *that* a password was used (`encrypted: true`) but not the password itself or any derivative.
- **Memory zeroisation is enforced.** Every struct that touches a password, a derived key, or plaintext export bytes implements `Drop` via the `zeroize` crate; tests assert that the destructor runs and clears the buffer.
- **AEAD authenticates the entire inner document.** A tamper to any byte of the ciphertext fails the tag check; we do not include a separate HMAC because the AEAD already provides authenticated encryption with associated data.
- **KDF parameters are bounded.** The decoder refuses files declaring parameters above a sanity ceiling (`m_cost_kib > 1_048_576`, `t_cost > 100`) so a malicious file cannot weaponize the importer into a memory-exhaustion DoS.
- **Plaintext export is loud.** The plaintext path is gated behind `accept_plaintext_exchange = true` per-mount config + an explicit `--allow-plaintext` flag; every plaintext export emits a separate `exchange_export_plaintext` audit event for SOC visibility. The GUI does not surface a plaintext export button at all.
- **Vault fingerprint in the envelope is non-secret** (it's a hash of a public quantity) but lets the importer surface a clear "this came from a different vault" warning, mitigating accidental cross-environment imports.
- **Preview tokens are random 256-bit values, single-use, 10-minute TTL, owner-bound.** A leaked preview token cannot be replayed by another actor.
- **File-payload caps.** Per-file 32 MiB cap (matching file-resources); per-export 1 GiB total cap. Both caps are enforced before any AEAD work runs so a malformed manifest cannot drive memory usage past the limit.
- **Side-channel exposure.** Argon2id is constant-time per algorithm; XChaCha20-Poly1305 is constant-time per RustCrypto. The password-strength check (length floor) runs in constant time relative to the password length; we deliberately do **not** check against a denylist of common passwords because that would either leak via timing or require shipping a 100MB list — operators who want denylist enforcement run an external policy in front.
- **Network exposure.** The `.bvx` is intended to be transmissible; the password must be transmitted out-of-band. The GUI nudges the user toward this with an inline help text on the export-result screen; documentation in `docs/docs/exchange.md` calls it out at the top.

## Tracking

Add a new roadmap row under **Operations** (or near "Import/Export & Backup/Restore"):

```
| Import / Export Module (user-facing JSON + password-encrypted .bvx) ([spec](features/import-export-module.md)) | Todo |
```

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md), and this file's "Current State" / phase markers.
