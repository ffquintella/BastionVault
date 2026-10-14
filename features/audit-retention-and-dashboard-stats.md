# Feature: Audit Retention and Precomputed Dashboard Statistics

## Summary

Three changes that stop the replicated audit stores from growing without bound
and stop request handlers from reading them whole:

1. **Audit retention** — every append-only audit store in the barrier keeps
   records for a configurable number of days (default **365**). A daily
   housekeeping job deletes what is older.
2. **Dashboard statistics** — the GUI Dashboard's audit numbers, 24-hour
   activity histogram and "Recent activity" list come from one persisted record
   that a background job recomputes every 10 minutes. No dashboard request scans
   an audit store.
3. **Bounded `sys/audit/events`** — without a `from` bound the endpoint reads the
   last 24 hours instead of every store from the beginning.

## Motivation

Production incident: `namespaces/<uuid>/sys/access-audit/` held 184,332 rows
(~55 MiB) and `denial-audit/` 34,940, with no retention. The Dashboard called
`sys/audit/events` with no window (`listAuditEvents("", "", 200)`), which ran an
unbounded read of every audit store on every page load and kept 200 rows; the
summary handler aggregated the same sources for its 24-hour counters. Storage
paging (T6) bounded each wire response, but time and memory still grew with the
data, on every dashboard view, on every node.

## Current State

**Shipped (Unreleased).** All three parts, tests, GUI and docs. See the phase
table below.

| Phase | Scope | Status |
|---|---|---|
| 1 | Retention config record + `v2/sys/audit-retention` (sudo) | Done |
| 2 | Daily housekeeping job: leader-only, catch-up, batched deletes, status record | Done |
| 3 | Dashboard statistics record, 10-minute refresh, summary served from it | Done |
| 4 | GUI Dashboard reads the summary only; freshness label | Done |
| 5 | `sys/audit/events` default 24-hour window | Done |

### What is not implemented

- A manual "run housekeeping now" trigger. Retention changes take effect at the
  next 00:00 UTC run.
- A GUI for the retention setting (API and CLI-over-HTTP only).
- Retention for the change-history stores (see "Scope" below).
- A key-range listing primitive in `bv-storage`: the pruner lists a store's keys
  (keys only, no values, no decryption) and filters them in memory.

## Upgrade Notes — destructive on upgrade

Retention is **on by default with 365 days**, as requested. A deployment that
has never written `v2/sys/audit-retention` therefore runs on the default, and
the first run after the upgrade permanently deletes every record in the pruned
stores older than a year — with no operator action. Mitigations shipped:

- The first run is the first 00:00 UTC **at least 24 hours** after the job arms
  (first start of the new version on the leader), never the same night: 24–48
  hours to configure. The endpoint cannot be written before upgrading (it is
  new), so this window is where an operator sets `retention_days` or
  `enabled: false`.
- Every node logs, at its first unsealed tick, a `security`-target **warning**
  when the default applies (“PERMANENTLY DELETED … the next at …”), or an info
  line with the stored setting.
- `GET v2/sys/audit-retention` reports `source: "default"` and `next_run_at`.
- Operator instructions: `CHANGELOG.md` (Changed → Upgrade notes) and
  `docs/configuration.md` (Audit Retention).

## Design

### Scope: which stores are pruned

The flat, append-only, timestamp-keyed stores under the system view. Their keys
start with 20-digit zero-padded nanoseconds since the epoch, so "older than the
cutoff" is a key comparison and no record has to be read or decrypted:

| Store | Sub-path | Key |
|---|---|---|
| access-audit | `access-audit/` | `<nanos>-<16 hex>` |
| denial-audit | `denial-audit/` | `<nanos>` |
| login-audit | `login-audit/` | `<nanos>` |
| user-audit | `identity/user-audit/` | `<nanos>` |
| share-history | `sharing/history/` | `<nanos>` |
| files-audit | `files-audit/` | `<nanos>` |
| ssh-sign-audit | `ssh-sign-audit/` | `<nanos>` |
| ssh-ca-audit | `ssh-ca-audit/` | `<nanos>` |

A key that does not start with 20 digits (optionally followed by `-`) is never
deleted; it is counted as `unrecognised` in the run report.

**Not pruned:** the policy, identity-group and asset-group change histories
(`{name}/{nanos}` keys). They record who changed a live object and how; they grow
with administrative changes rather than with requests, and deleting their oldest
rows would remove the provenance of objects that still exist. The hash-chained
`audit.log` file device (`bv-audit`) is untouched — rotation already bounds it.

### Retention configuration

Runtime, replicated, sudo-gated: `GET`/`POST`/`PUT` `v2/sys/audit-retention`
(logical path `sys/audit-retention`, in `root_paths`). Persisted in the barrier at
`sys/audit-retention/config`:

```json
{ "version": 1, "retention_days": 365, "enabled": true,
  "updated_at": "2026-10-14T09:00:00Z", "updated_by": "root" }
```

- `retention_days`: integer, `1` ≤ n ≤ `36500`. `0`, negatives, non-integers and
  anything above the maximum are refused with 400. `0` never means "delete
  everything" and never means "keep forever".
- `enabled = false` keeps every record forever; the job still runs and records
  `outcome: "disabled"`.
- Missing record ⇒ the built-in default (365 days, enabled), reported as
  `source: "default"`.
- An unreadable or unknown-version record is an error, not a fallback to the
  default: the job refuses to delete and records `outcome: "failed"`. A default
  of 365 days could delete records an operator configured to keep for longer.
- Partial updates: a write may carry either field; the other keeps its value.

Rejected alternative: an HCL setting. Each node reads its own HCL, so two nodes
could disagree and retention would change with Raft leadership; `Core` also does
not keep the parsed config for kernel modules. The replicated record is one
answer for the whole cluster.

### Housekeeping job

One detached task per process (`modules/system/housekeeping.rs`), started from
the system module's `start_background` once per module instance, ticking every
60 seconds and skipping while sealed.

- **Single runner.** Each tick asks `bv_storage::cluster::status` for this node's
  Raft role: the leader runs, followers skip, a non-clustered node runs. There
  is no distributed lock; both jobs are idempotent (deleting an already-deleted
  key is a no-op, a stats refresh overwrites a derived record), so the window in
  which a deposed leader still believes it leads costs duplicate work, not
  wrong results.
- **Schedule.** Daily at **00:00 UTC** (the codebase stores and compares UTC
  everywhere). The status record keeps `armed_at` (first time any node saw the
  job) and `last_run.started_at`. A run is due when the most recent 00:00 UTC is
  later than `last_run.started_at` — or, before the first run, later than
  `armed_at + 24h`. A fresh install or an upgrade therefore waits for the first
  midnight at least a day away (see Upgrade Notes); a node that was down at
  midnight runs at its first tick after it comes back (catch-up), once.
- **Clock check.** The cutoff is the runner's wall clock minus the retention.
  Before deleting, the run lists every store and takes the newest record across
  all of them; if the runner's clock is more than **2 days** past it, nothing is
  deleted and the run reports `refused` (logged on `security`, recorded in the
  status). Rule chosen: the access, denial and login stores are written
  continuously by every node in a live deployment, so the gap is normally
  minutes and a large one means the clock jumped ahead (which would delete
  early) or the deployment is idle (nothing is growing, so waiting is free). The
  reference is deployment-wide, not per store, because a single store (SSH CA)
  can legitimately be quiet for months and must still be pruned. A clock that
  is consistently wrong on every node cannot be detected this way.
- **Batches.** Expired keys are deleted oldest first, 500 per batch, with a 50 ms
  pause between batches and a seal check before each batch. Each delete is one
  barrier delete, so no transaction or response grows with the backlog.
- **Logging.** One `info` line per store on the `security` target with the store
  name, deleted / remaining / unrecognised counts and the cutoff; one summary
  line per run. No record content is ever logged.
- **Status.** `sys/audit-retention/status` holds the last run's report (start,
  finish, cutoff, retention, outcome, per-store counts and errors, node id) and
  is returned by `GET v2/sys/audit-retention` together with the next scheduled
  run.

### Dashboard statistics record

`sys/dashboard-stats/record`, JSON with a `version` field (`1`):

| Field | Meaning |
|---|---|
| `computed_at` | RFC3339 UTC instant the record describes |
| `window_start` | `computed_at - 24h` |
| `compute_ms` | how long the computation took |
| `audit_24h_total` | events across every source in the 24-hour window |
| `audit_24h_denied` | denials in the window |
| `failed_logins_1h` | failed logins in the hour before `computed_at` |
| `histogram_24h` | 24 hourly counts, oldest first; bucket `i` covers `[window_start + i h, window_start + (i+1) h)` |
| `recent` | newest 20 events (the `sys/audit/events` row shape) from the last 24 hours, widened to 7 days when the day has fewer than 20 |
| `partial` | `true` when an audit source could not be read (additive in version 1, `serde(default)` = `false`) |
| `failed_sources` | the sources that could not be read (`policy`, `access`, …) |

Same sources and same arithmetic as the old on-the-fly summary, computed with
the bounded `since` range scans. The record is derived data: whichever node is
the runner rewrites it in its own version, a reader that does not recognise the
version reports it as not computed rather than guessing.

Refresh: on the first tick after start (so a missing record is computed at
startup) and whenever `computed_at` is 10 minutes old or more.

### `sys/dashboard/summary`

Mount / policy / entity counts stay live and ACL- and namespace-scoped as
before. The audit numbers come from the record and stay deployment-wide, in two
visibility tiers:

- `audit_24h`, `attention` and `audit_stats` without rows: `read`, `sudo` or
  root on `sys/audit/events` — the gate the counters always had.
- `audit_stats.recent` and `audit_stats.histogram_24h`: exactly what
  `sys/audit/events` requires (a Read on a sudo-gated root path): `read` and
  `sudo`, or root. The histogram is in this tier because it used to be built in
  the GUI from those rows. (Security review: the first version gated the rows on
  `read` alone, which let a caller refused by `sys/audit/events` read its 20
  newest rows here.)

New block `audit_stats`:

```json
"audit_stats": { "state": "ready", "version": 1, "computed_at": "...",
  "age_secs": 120, "stale": false, "window_start": "...",
  "histogram_24h": [ ... 24 ... ], "histogram_bucket_secs": 3600,
  "recent": [ ... ], "refresh_interval_secs": 600 }
```

When the record is absent, of an unknown version, unreadable or the read fails,
`audit_stats` is `{ "state": "pending", "reason": "not_computed" |
"unsupported_version" | "unreadable" | "storage_error" }` and the `audit_24h` /
`attention` blocks are omitted. The handler never falls back to scanning.
`stale` is true when the record is 30 minutes old or more (three missed
refreshes). `partial` / `failed_sources` say an audit source could not be read
when the record was computed — the collectors used to skip such a source
silently and under-count; `sys/audit/events` returns `failed_sources` too, and
the GUI marks the numbers *partial*. `audit_24h.write_failures` stays the live
per-node counter.

These fields are additive on an existing BastionVault-specific endpoint (it is
not part of the Vault API), served on both prefixes because the summary already
was. Rejected alternative: a separate `v2/sys/dashboard/stats` route — two round
trips and two copies of the audit-visibility gate to keep in step.

### `sys/audit/events`

Without `from`, the window is the 24 hours before `to` (or before now). An
explicit `from` is honoured as before. The response gains `from`, the bound that
was applied. This is a bug fix on a route that exists under `v1/` too: an
unbounded read of every audit store is the defect.

## Security Considerations

- Deletion of audit records is security-relevant: it runs only on the elected
  runner, only from the replicated, sudo-gated configuration, logs counts per
  store on the `security` target, and records each run in the status record.
  The configuration write itself is an audited request.
- No record content is logged; the stats record is barrier-encrypted like the
  stores it summarises and is shown only to audit-capable callers.
- Failure is explicit: an unreadable configuration stops deletion; a failed
  store is reported with its error while the others proceed.

## Testing

- `bv-kernel` unit tests: retention validation, schedule (`run_due`, catch-up,
  first-run grace, `next_run_at`), clock check, key classification and
  boundary, startup announcement, stats record decode (missing, unknown
  version, corrupt, pre-`partial` v1), histogram/recent building, detail gate
  and partial marker in the summary block.
- `src/engine_tests/audit_retention.rs`: config round-trip and validation over
  HTTP, sudo gate, pruning across all eight stores, boundary records kept,
  batches, idempotence, configuration changes, follower skip, clock check
  refusal and recovery.
- `src/engine_tests/dashboard_stats.rs`: computed record equals the on-the-fly
  aggregation over a seeded dataset; summary serves the stored record; pending
  state for absent and unknown-version records; denials and failed logins from
  storage; `sys/audit/events` default window; a `read`-only caller on
  `sys/audit/events` gets the counters but no rows or histogram, `read`+`sudo`
  gets both.
- `gui/src/test/dashboard.test.tsx`: the Dashboard renders counts, histogram and
  recent activity from the summary, shows freshness and the pending state, and
  never calls `list_audit_events`.
