# Feature: Scheduled Exports — Exportable Backups via the Exchange Module

## Summary

Extend the existing backup subsystem ([features/import-export-backup-restore.md](import-export-backup-restore.md)) with a **scheduler** that drives the new Exchange module ([features/import-export-module.md](import-export-module.md)) on a recurring cadence to produce **exportable, password-protected `.bvx` backups**. Where the existing BVBK backup is the operator's *disaster-recovery* primitive (binary archive, HMAC'd with the vault's audit-device key, restorable only against the same vault's barrier), scheduled `.bvx` exports are the *portable* backup primitive — restorable on any BastionVault instance with the password, sendable off-site through any storage target, and inspectable in plain JSON after decryption.

The feature ships in five capabilities:

1. **Schedule definitions** — named, cron-expressed, persisted, audit-logged. Each schedule owns a scope (which mounts/resources/groups), an output target (local path or cloud-storage target), a retention policy, and a sealed password reference.
2. **A scheduler runtime** — single-instance-elected (HA-safe via the existing Hiqlite Raft leader), tokio-driven, with per-schedule isolation and structured failure handling.
3. **Retention** — count-based, age-based, and grandfather-father-son (GFS) policies.
4. **Verification** — every Nth produced `.bvx` is round-tripped through a decrypt-and-validate step before retention is allowed to drop the prior verified backup.
5. **Cloud-target integration** — schedules can write directly to the existing cloud-storage backends ([roadmap.md:32](roadmap.md:32)) so off-site backups are first-class.

A scheduled export is intentionally **not** a BVBK replacement. The two coexist: BVBK for fast, full-vault disaster recovery on the same binary; scheduled `.bvx` exports for portability, compliance evidence, off-site rotation, and "I lost the vault, can I rebuild from a file" workflows.

## Motivation

- **The Exchange module is a one-shot primitive**; scheduled, hands-off backups are what operators ask for in production. Today's two answers — "set up cron and call the CLI" or "back up the storage backend at the OS level" — are both fragile and neither one captures Vault-level metadata properly.
- **`.bvx` is a better off-site backup format than BVBK** for a meaningful slice of customers. It is portable across vault instances, decryptable with a password, inspectable in JSON after decryption, and version-stable — three properties BVBK explicitly does not have. Operators who today scp BVBK files to S3 are using BVBK as a portability format it isn't designed to be.
- **Compliance evidence wants periodic snapshots, not ad-hoc ones.** SOC 2 CC8.1 (change-management evidence), ISO 27001 A.8.13 (information backup), PCI-DSS 9.5 (offline backup), and HIPAA §164.308(a)(7) (data-backup plan) all expect a documented, auditable, *recurring* backup process. The Compliance Reporting module ([features/compliance-reporting.md](compliance-reporting.md)) already plans to consume snapshot evidence; scheduled exports are the natural producer.
- **Aligns with infrastructure already in place.** The cloud-storage backend ([features/cloud-storage-backend.md](cloud-storage-backend.md)) already speaks S3 / OneDrive / Google Drive / Dropbox via the `FileTarget` trait. Hiqlite already gives us a leader-elected runtime to host the scheduler. The Exchange module already produces `.bvx`. This feature is mostly **glue** — a small scheduler that ties existing components together.
- **Builds on, does not replace, BVBK.** Operators who want true point-in-time DR continue to schedule BVBK. Operators who want portable / off-site / compliance-friendly snapshots schedule `.bvx`. Operators who want both schedule both — the runtime supports either format per schedule.

## Current State

- **Existing backup pieces**:
  - `src/backup/{format,create,restore,export,import}.rs` — BVBK binary + plaintext-JSON export. CLI `bvault operator backup/restore/export/import`. HTTP `POST /v1/sys/{backup,restore}` + `GET /v1/sys/export/<path>` + `POST /v1/sys/import/<mount>`.
  - **No scheduler.** No persisted schedule entries. No leader-elected periodic runner. Operators wire `cron` + the CLI by hand.
  - **No retention.** Output files accumulate forever unless an operator prunes them externally.
  - **No verification.** A backup is assumed good until restore time proves otherwise.
- **Exchange module** ([features/import-export-module.md](import-export-module.md)) is currently a spec, not yet implemented. This feature **depends on** Phase 2 of Exchange (the `.bvx` envelope) being shipped before Phase 1 of this feature can land. The order is documented under "Implementation Scope".
- **Cloud-storage backend** ([features/cloud-storage-backend.md](cloud-storage-backend.md)) is shipped with `FileTarget` + the four provider implementations. We reuse that trait directly — no new transport code.
- **Hiqlite leader election** is shipped (HA via Raft consensus is `Done` per [roadmap.md:52](roadmap.md:52)). The scheduler hooks the existing leader-changed signal so only one node runs each schedule.

## Design

### Schedule Object

A schedule is a persisted, barrier-encrypted document describing **what** to export, **when**, **where to put it**, **how long to keep it**, and **how to encrypt it**:

```json
{
  "id": "uuid-...",
  "name": "nightly-secret-bundle",
  "namespace": "engineering/platform",
  "cron": "0 3 * * *",                              // 03:00 daily, server local time
  "format": "bvx",                                  // "bvx" | "bvk" | "plaintext-json"
  "scope": {
    "kind": "selective",
    "include": [
      { "type": "kv_path",        "mount": "secret/", "path": "" },
      { "type": "resource_group", "id": "uuid-..." }
    ]
  },
  "encryption": {
    "method": "password_ref",
    "password_ref": {
      "kind":  "transit",
      "key":   "transit:backup-password/nightly",
      "param": "current_version"
    }
  },
  "destinations": [
    { "kind": "local_path",  "path": "/var/backups/bvault/nightly" },
    { "kind": "cloud_target", "target": "primary-s3", "prefix": "bvault/nightly/" }
  ],
  "retention": {
    "policy": "gfs",
    "keep_daily":   7,
    "keep_weekly":  4,
    "keep_monthly": 12,
    "keep_yearly":  3,
    "min_verified": 1
  },
  "verification": {
    "every_nth_run":   1,
    "decrypt_and_parse": true,
    "scope_sample":    "first_10",
    "fail_action":     "alert_and_retain_prior"
  },
  "owner_entity_id": "...",
  "created_at": "2026-04-25T12:00:00Z",
  "updated_at": "2026-04-25T12:00:00Z",
  "enabled":   true
}
```

### Encryption: Where Does the Password Live?

A scheduled export is unattended — by definition no human is around at 03:00 to type a password. Three supported modes for sourcing the encryption password:

1. **`password_ref.kind = "transit"`** *(recommended)*. The password is generated *per run* by a `Transit` ML-KEM-768-derived random + Argon2id-binding step: the scheduler asks Transit to mint a 32-byte random datakey at run time, derives the export password from it, encrypts with that password, and stores the wrapped datakey **inside the `.bvx` envelope's `comment` field as base64**. Recovery requires both the `.bvx` *and* the Transit key to decapsulate the wrapped datakey back to the password. This pattern gives "rotateable password" semantics for free — rotate the Transit key, all subsequent backups use the new lineage; old backups still decrypt against their own embedded wrapped datakey + the matching old Transit version.
2. **`password_ref.kind = "static_secret"`**. The password is read from a KV path the scheduler has read access to. Simpler, but the password is shared across runs; rotation means re-encrypting old files or accepting that they all share one password.
3. **`password_ref.kind = "external_kms"`**. The password is fetched from an external KMS (AWS KMS, Azure Key Vault, GCP KMS) at run time. Useful when an organisation already runs a KMS as the root of trust. Out of scope for Phase 1.

The default and the GUI's recommended path is `transit`. The `static_secret` path exists for operators who want simplicity at the cost of rotation flexibility.

### Scheduler Runtime

- One **scheduler task** per BastionVault process, started at unseal time, gated on the Hiqlite leader signal. Followers do nothing; on leader change, the new leader picks up the schedules from storage on its next tick.
- Schedules tick on a 30-second cadence; each schedule's `cron` is parsed via `cron` (pure-Rust crate) and the next-fire time computed. A schedule fires at most once per cron-resolved instant even if the scheduler woke up late (we never double-fire on catch-up).
- **Per-schedule isolation**: each run is its own tokio task with its own panic boundary; one schedule's failure cannot stall others.
- **Run records** are persisted at `scheduled_exports/runs/<schedule_id>/<rfc3339>` with status (`success`, `failed`, `verified`, `verify_failed`) plus error text + cumulative byte count. The records themselves drive the GUI history view + retention math.
- **Concurrent run protection**: each schedule has a Hiqlite-backed lock (`scheduled_exports/locks/<schedule_id>`) acquired before the run starts, released when the run record is written. A leader change mid-run does not produce two concurrent runs because the Raft-replicated lock is observed by the new leader.
- **Catch-up policy**: if the scheduler was asleep (process restart, leader transition) longer than a single cron interval, by default we run **one** missed instance, not all of them. Configurable per schedule via `catch_up = "single" | "all" | "none"`.

### Retention Policies

Three policies, exclusive per schedule:

- **`count`** — keep the last N runs; everything older is removed.
- **`age`** — keep runs newer than `keep_for = "30d"`; everything older is removed.
- **`gfs`** *(default for compliance-aligned schedules)* — Grandfather-Father-Son. Configurable via `keep_daily`, `keep_weekly`, `keep_monthly`, `keep_yearly`. The retainer marks the most recent run on each cycle boundary as protected; everything else falls under the daily count.

Retention runs **after** verification (see below) so a verify-failed backup never knocks an older verified backup out of retention. The retainer always preserves at least `min_verified` runs that have a `verified` status, regardless of count/age math; this guarantees there is always something restorable.

### Verification

A backup that has never been decrypted is a backup you don't know if you have. Each schedule declares a verification policy:

- **`every_nth_run`** — verify every Nth produced `.bvx`. `1` means every run; `7` means every seventh; `0` disables (with an explicit warning at schedule creation time).
- **`decrypt_and_parse`** — actually decrypt the file, parse the inner JSON, and assert the schema validates. This is the real signal — file-existence-and-size checks are useless in this domain.
- **`scope_sample`** — `first_10` reads the first 10 items, decrypts their values via the destination KV, and compares; `none` skips content sampling; `all` verifies every item but is expensive on large exports.
- **`fail_action`** — `alert_and_retain_prior` (default; emit an audit + metrics event, do not let retention drop the most recent verified file) or `alert_and_proceed` (just alert).

Verification runs *immediately after* the export completes, against the file the scheduler just produced, before the file is uploaded to the cloud destination. If verification fails the file may still be uploaded (so the operator has it for forensics) but the run record carries `verified=false`, and retention won't treat it as the latest verified backup.

### Destinations

A schedule can have one or more destinations. The runner produces the `.bvx` once and writes it to each destination atomically:

- **`local_path`** — write to a directory on the BastionVault host. Atomic via tmp-then-rename.
- **`cloud_target`** — push to an existing cloud-storage backend ([features/cloud-storage-backend.md](cloud-storage-backend.md)) using the `FileTarget` trait. Reuses OAuth tokens, key obfuscation, and retry behaviour the cloud-storage feature already ships.
- **`http_webhook`** — POST the `.bvx` to a configured URL with the schedule metadata. Out of scope for Phase 1.

Each destination tracks its own success/fail status in the run record; a partial failure (succeeded on `local_path`, failed on `cloud_target`) is logged distinctly and *retried* on the next run (the missed-upload is added to a small per-destination queue, oldest-first).

### HTTP Surface

```
LIST   /v1/sys/scheduled-exports                              # list schedules
POST   /v1/sys/scheduled-exports                              # create
GET    /v1/sys/scheduled-exports/<id>                         # read
PATCH  /v1/sys/scheduled-exports/<id>                         # update
DELETE /v1/sys/scheduled-exports/<id>                         # delete (refused unless force=true)
POST   /v1/sys/scheduled-exports/<id>/enable
POST   /v1/sys/scheduled-exports/<id>/disable
POST   /v1/sys/scheduled-exports/<id>/run-now                 # ad-hoc run, separate from cron
LIST   /v1/sys/scheduled-exports/<id>/runs                    # run history
GET    /v1/sys/scheduled-exports/<id>/runs/<run_id>           # one run + verification result
GET    /v1/sys/scheduled-exports/<id>/runs/<run_id>/download  # download the produced .bvx
POST   /v1/sys/scheduled-exports/<id>/verify-now/<run_id>     # force a re-verify of an existing run
```

### CLI Surface

```
bvault scheduled-export create   --name nightly-secret-bundle    \
                                 --cron "0 3 * * *"              \
                                 --scope kv:secret/myapp/        \
                                 --destination local:/var/backups/bvault \
                                 --destination cloud:primary-s3/bvault/nightly/ \
                                 --retention gfs:7d/4w/12m/3y    \
                                 --password-ref transit:backup-password/nightly

bvault scheduled-export list
bvault scheduled-export show     <id>
bvault scheduled-export disable  <id>
bvault scheduled-export run-now  <id>
bvault scheduled-export runs     <id>
bvault scheduled-export download <id> <run_id> --output ./nightly-2026-04-25.bvx
bvault scheduled-export verify   <id> <run_id>
```

### GUI

A new top-level page `/scheduled-exports`:

- **List view**: table of schedules with name, namespace, cron, last run, last-verified status, next fire time, and enabled toggle.
- **Detail view**: schedule metadata + a recent-runs panel (status, duration, byte count, verified bool, destination breakdown).
- **Create / edit modal**:
  - Cron picker (with a "describe in plain English" preview powered by `cronstrue`).
  - Scope picker (reuses `ExchangeScopePicker` from the Exchange module).
  - Destination picker (reuses the cloud-target picker from the cloud-storage feature).
  - Retention selector with sensible defaults per use-case ("Nightly compliance" → GFS 7/4/12/3; "Daily off-site" → count=14; "Hourly during incident" → age=72h).
  - Password-ref picker — defaults to "Generate via Transit" with a key-name input; expert mode exposes static-secret + external-KMS forms.
- **Run-now button** + **download** + **verify-now** all driven from the detail view.
- **Audit drill-down**: every schedule action links to filtered audit events.

### Module Architecture

```
src/modules/scheduled_exports/
├── mod.rs                          -- ScheduledExportsModule; sys path + scheduler boot
├── store.rs                        -- ScheduleStore: CRUD + per-namespace scoping
├── runner.rs                       -- per-schedule run task; coordinates exchange + destinations + retention
├── scheduler.rs                    -- top-level tick loop; leader-gated; cron parsing; lock acquisition
├── retention.rs                    -- count / age / gfs algorithms
├── verifier.rs                     -- decrypt-and-parse + scope-sample
├── destination/
│   ├── mod.rs                      -- DestinationWriter trait
│   ├── local_path.rs               -- atomic tmp-then-rename
│   └── cloud_target.rs             -- bridge to FileTarget
├── password_ref/
│   ├── mod.rs                      -- PasswordRefResolver trait
│   ├── transit.rs                  -- ML-KEM-768-wrapped datakey path
│   └── static_secret.rs            -- KV-path-read path
├── audit.rs                        -- scheduled_export_run / verify / retain event emitters
└── path_*.rs                       -- /v1/sys/scheduled-exports/* HTTP handlers
```

### Audit Schema

New event types, joining the existing audit pipeline:

- `scheduled_export_run` — `{ schedule_id, schedule_name, run_id, format, scope, destinations: [...], item_count, byte_count, duration_ms, status }`.
- `scheduled_export_verify` — `{ schedule_id, run_id, verified: bool, scope_sample, error?: string }`.
- `scheduled_export_retain` — `{ schedule_id, retained: [run_id...], removed: [run_id...] }`.
- `scheduled_export_password_used` — emitted when the runner resolves a password-ref. Records which Transit key (or KV path) was consulted; never the password itself.

### Interplay with Existing Features

- **Exchange module** ([features/import-export-module.md](import-export-module.md)) is the producer. The runner calls `exchange::format::Exporter::export(scope, password) -> Vec<u8>`. No new format code lives here.
- **Cloud-storage backend** ([features/cloud-storage-backend.md](cloud-storage-backend.md)) is the destination. The runner calls `FileTarget::put(path, bytes)` for cloud destinations. No new transport code lives here.
- **Hiqlite HA**: leader signal gates the scheduler. Schedule storage + lock are Raft-replicated, so schedules persist across leader transitions and locks prevent concurrent runs.
- **Compliance Reporting**: scheduled-export run events are consumed by the SOC 2 CC8.1 + ISO 27001 A.8.13 + PCI-DSS 9.5 + HIPAA §164.308(a)(7) reports automatically — no special-case wiring. The Compliance Reporting feature already specifies that `dynamic_secret`, `audit`, and now `scheduled_export_*` events feed the change-management section.
- **Namespaces** ([features/namespaces-multitenancy.md](namespaces-multitenancy.md)): a schedule lives inside one namespace and exports only that namespace's data. Cross-namespace exports require an actor with `child_visible=true` who creates the schedule in the parent namespace; the runner inherits that scope.
- **Per-user scoping** ([features/per-user-scoping.md](per-user-scoping.md)): the schedule's `owner_entity_id` is the actor whose ACL is used at run time. If the owner is later removed, the schedule auto-disables and emits a high-priority alert.
- **BVBK backup**: completely independent. A BastionVault deployment can have BVBK schedules *and* `.bvx` schedules; they share storage of run records but nothing else. BVBK schedules use this same scheduler runtime via `format = "bvk"` (Phase 4 deliverable) — i.e. the scheduler is format-agnostic and can drive either producer.

## Implementation Scope

**Dependency on the Exchange module**: this feature requires Phase 2 of [features/import-export-module.md](import-export-module.md) (the `.bvx` envelope) to be shipped before Phase 1 of this feature can produce encrypted output. Phase 1 ships the scheduler runtime + plaintext-JSON exports; Phase 2 adds `.bvx` once the Exchange module's envelope work lands.

### Phase 1 — Scheduler Runtime + Plaintext JSON Exports

| File | Purpose |
|---|---|
| `src/modules/scheduled_exports/mod.rs` | Module + sys path registration. |
| `src/modules/scheduled_exports/store.rs` | Schedule CRUD. |
| `src/modules/scheduled_exports/scheduler.rs` | Tick loop + leader-gated startup + cron parser. |
| `src/modules/scheduled_exports/runner.rs` | Per-schedule run task. |
| `src/modules/scheduled_exports/destination/{mod,local_path}.rs` | Local-path destination only. |
| `src/modules/scheduled_exports/audit.rs` | New audit event types. |
| `src/modules/scheduled_exports/path_*.rs` | HTTP handlers. |
| `src/cli/command/scheduled_export_*.rs` | CLI commands. |

Dependencies:

```toml
cron       = "0.12"   # cron expression parser, pure Rust
cronstrue  = "0.4"    # human-readable cron description (used by GUI; small)
chrono     = "0.4"    # already in tree
```

### Phase 2 — `.bvx` Output + Transit Password-Ref

Requires Exchange Phase 2 shipped.

| File | Purpose |
|---|---|
| `src/modules/scheduled_exports/password_ref/{mod,transit,static_secret}.rs` | Password-ref resolvers. |
| `src/modules/scheduled_exports/runner.rs` (extension) | Switch to `.bvx` output; embed wrapped datakey in `comment`. |

### Phase 3 — Retention + Verification

| File | Purpose |
|---|---|
| `src/modules/scheduled_exports/retention.rs` | count / age / gfs policies. |
| `src/modules/scheduled_exports/verifier.rs` | Decrypt-and-parse + scope-sample. |
| `src/modules/scheduled_exports/runner.rs` (extension) | Verify-then-retain ordering. |

### Phase 4 — Cloud Destinations + BVBK Format Support

| File | Purpose |
|---|---|
| `src/modules/scheduled_exports/destination/cloud_target.rs` | `FileTarget` bridge. |
| `src/modules/scheduled_exports/runner.rs` (extension) | `format = "bvk"` path; calls existing `src/backup/create.rs`. |

### Phase 5 — GUI

| File | Purpose |
|---|---|
| `gui/src/routes/ScheduledExportsPage.tsx` | List + detail view. |
| `gui/src/components/ScheduledExportEditor.tsx` | Create/edit modal. |
| `gui/src/components/CronPicker.tsx` | Cron expression input with cronstrue preview. |
| `gui/src/components/RetentionEditor.tsx` | Count / age / GFS picker. |
| `gui/src/lib/api.ts` (extension) | Typed wrappers. |

### Not In Scope

- **External KMS password-ref** (AWS KMS / Azure Key Vault / GCP KMS). Tracked as a follow-up after the framework ships.
- **HTTP webhook destination**. Same reason.
- **In-process restore from a `.bvx` file the scheduler produced.** Restore goes through the standard Exchange import-preview-then-apply flow; we don't add a separate "restore from scheduled run" endpoint to avoid duplicating that workflow.
- **Differential / incremental scheduled exports.** The Exchange module is full-snapshot-per-export by design; differential exports are listed there as out-of-scope for v1.
- **Cross-cluster fan-out.** A schedule runs on one BastionVault cluster and writes to that cluster's destinations. Operators who run multiple clusters create schedules on each.
- **GUI for editing the BVBK schedule format directly.** Phase 4 supports `format = "bvk"` through the API + CLI; GUI exposes BVBK only as a destination-level toggle, not as a separate edit surface, to keep the page understandable.

## Testing Requirements

### Unit Tests

- Cron parser round-trip across DST boundaries (`Europe/Berlin` last Sunday of March / October).
- Catch-up policy: schedule fires at most once per missed instant under `single`; fires every missed instant under `all`; never fires under `none`.
- Retention algorithms: GFS keeps the right files for a synthetic 5-year run history; count / age policies match their specs exactly on edge cases (boundary overlap, time jumps).
- Lock acquisition: two concurrent calls to acquire the same schedule's lock — one wins, the other returns `LockBusy` cleanly.
- Verifier: decrypt-and-parse on a known good `.bvx` returns `verified=true`; on a bit-flipped ciphertext returns `verified=false` with a `decryption_failed` error; on a structurally valid `.bvx` whose inner schema is malformed returns `verified=false` with `schema_invalid`.
- Password-ref `transit` path: per-run wrapped datakey embedded in `comment`; recovery decapsulates correctly with the matching Transit version; rotation produces a new lineage without breaking old files.

### Integration Tests

- Create a schedule firing every minute, wait two ticks, confirm two run records, confirm both produce `.bvx` files at the local destination, confirm both verify.
- Leader-transition test: kill the scheduler leader mid-run, confirm a different node picks up after the next tick and that no double-run happens (the lock is observed).
- Retention end-to-end: schedule with `count=3`; produce 5 runs over 5 minutes; confirm 2 oldest are pruned, 3 newest remain.
- Cloud destination: bind to a localstack-S3 in CI; confirm the produced `.bvx` lands at the configured prefix; force an upload failure (kill localstack) and confirm the missed-upload queue retries on the next run.
- Verify-then-retain: induce a verification failure on the latest run; confirm retention does NOT drop the prior verified file; confirm the next successful run resumes normal retention.

### Cucumber BDD Scenarios

- Operator creates a "Nightly Compliance" schedule via the GUI: cron `0 3 * * *`, GFS retention 7/4/12/3, two destinations (local + S3). Next morning the run record shows `verified=true`, both destinations succeeded, and the file decrypts with the Transit-derived password.
- Operator deletes a schedule; the deletion is refused because it has run records; passes `force=true`; deletion succeeds and the run records are tagged orphaned but not auto-deleted (the operator can remove them separately).
- A leader transition happens during a 90-second export; the next tick on the new leader does not start a duplicate run; the run record reflects the failure of the killed run plus a retry on the next cron instant.
- Compliance auditor runs the SOC 2 CC8.1 report for the previous quarter; the report shows the 90 nightly export events plus their verification statuses.

### Negative Tests

- Cron expression that resolves to "never fires" (e.g. `0 0 30 2 *`): rejected at create-time with a clear explanation.
- Schedule with zero destinations: rejected.
- Schedule with `verification.every_nth_run = 0`: accepted with a warning event but no error.
- Schedule whose `password_ref.kind = "transit"` points at a non-ML-KEM-768 Transit key: rejected at create-time.
- Schedule whose owner has been deleted: schedule auto-disables on the next tick + emits an alert; subsequent ticks do not run.
- Run-now while a scheduled run is in progress: rejected with `run_in_progress`.

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`**: same constraint as every other module. CI must fail if either becomes reachable.
- **Schedule storage is barrier-encrypted.** Schedule records, run records, and the missed-upload queue all live under the standard barrier prefix.
- **Passwords are never logged.** The `scheduled_export_password_used` audit event records *which key* (Transit key name or KV path) was consulted, never the resolved password. Memory zeroisation runs on the resolved-password buffer immediately after the AEAD step.
- **Transit-wrapped datakeys are forward-secret across rotations.** Rotating the Transit key produces a new lineage; old files still decrypt against their own embedded wrapped datakey + the matching old Transit version, but a future compromise of the new key cannot retroactively decrypt them. Operators should treat the Transit key as a long-lived root of trust and rotate on a documented cadence (≥ once per year for most compliance frameworks).
- **Leader gating prevents split-brain runs.** The scheduler obeys the Hiqlite leader signal; followers do not run schedules even if their internal clock fires the cron. The Raft-backed lock is a defence-in-depth; even if two nodes briefly think they are leader, only one acquires the per-schedule lock.
- **Verification is part of the threat model.** A backup that is never verified is a backup you cannot trust. Schedules with `verification.every_nth_run = 0` emit a creation-time warning; the GUI marks them with a yellow flag in the list view. Auditors looking at the `scheduled_export_verify` events will see a gap immediately.
- **Cloud destinations carry their own threat model**, inherited from [features/cloud-storage-backend.md](cloud-storage-backend.md). The scheduler does not weaken any of those guarantees; the `.bvx` is encrypted before it ever reaches the cloud transport, so a cloud-side compromise yields ciphertext only.
- **Run records do not include the export bytes.** The bytes are written to the destination(s); the run record stores only metadata + status. A compromise of the run-records storage leaks "we backed up at this time and it succeeded," not "here is what we backed up." This separation matters because run-records storage is queried more often than the destination storage and may be exposed via more endpoints.
- **Catch-up amplification protection.** A long-asleep scheduler with `catch_up = "all"` and a 1-minute cron could in principle fire thousands of runs at once on wake. The runner caps catch-up at 100 instants regardless of `catch_up`; beyond that, missed instants are skipped and a `scheduled_export_catchup_overflow` audit event is emitted.
- **Schedule deletion is a soft delete by default.** Setting `enabled=false` halts runs; full deletion requires `force=true` plus an audit-logged confirmation. Run records survive a soft delete; full deletion of run records is a separate operation with its own audit event.

## Tracking

Add a roadmap row near the existing Backup row:

```
| Scheduled Exports (cron-driven `.bvx` / BVBK with retention + verification) ([spec](features/scheduled-exports.md)) | Todo |
```

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md), and this file's "Current State" / phase markers.
