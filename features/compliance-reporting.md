# Feature: Compliance Reporting

## Summary

Add a first-class **Compliance Reporting** subsystem that turns the audit log + identity + mount + policy state into auditor-ready reports for the standards BastionVault customers actually have to certify against: **SOC 2 (CC-series)**, **ISO/IEC 27001:2022 Annex A**, **PCI-DSS v4.0**, **HIPAA Security Rule**, **NIST SP 800-53 rev 5** (FedRAMP / FISMA), and **LGPD / GDPR**. The subsystem ships as a new BastionVault module (not a secret engine) plus a dedicated Compliance section in the GUI.

The deliverable is **three layers**:

1. **A query layer** (`/v1/compliance/query`) that lets evidence collectors ask structured questions over audit + state ("who accessed `secret/prod/*` in window W", "all entities with policy P", "every mount whose seal is below FIPS-140-3 level X") without manually grepping audit logs.
2. **A pre-built reports layer** (`/v1/compliance/reports/<framework>/<control>`) that emits machine-readable evidence packages mapped to specific control IDs (e.g. `soc2/CC6.1`, `iso27001/A.5.15`, `pcidss/7.2.1`, `nist80053/AC-2(1)`).
3. **An export layer** that bundles a date-windowed evidence package as a signed `.bvev` (BastionVault Evidence) file -- HMAC + ML-DSA-65 signature, deterministic JSON inside, suitable for handing to an auditor or attaching to a GRC platform.

The subsystem is read-only -- it never mutates state, never shells out to external services, and runs entirely on the same pure-Rust stack the rest of BastionVault uses.

## Motivation

- **Compliance is the #1 buyer driver for vault-class products** in regulated verticals (finance, healthcare, gov). Customers don't pick a vault on its API ergonomics; they pick it because the auditor signs off on the evidence it produces.
- **Today the data exists but the answer doesn't**: audit logs ([src/modules/audit/](../src/modules/audit), per CLAUDE.md), policy state, mount table, identity entities, lease records -- between them, every fact an auditor could ask is recorded. But no auditor wants to grep JSONL files. Without a reporting layer, every customer either writes their own ETL pipeline or punts the audit and uses a different vault.
- **Map once, reuse forever**: control-mapping work (SOC 2 CC6.1 → "list of every credential issuance + the actor + the policy that allowed it, for the audit window") is *exactly* the kind of work that benefits from being centralised in the product instead of redone in every customer's GRC consultancy engagement.
- **Signed evidence packages close the chain of custody**: an exported package signed with the vault's ML-DSA-65 identity key proves to the auditor that the evidence wasn't doctored between BastionVault and the auditor's desk. This is a real friction point in current Vault deployments where evidence is hand-massaged in spreadsheets.
- **Aligns with the PQC story**: signing evidence packages with ML-DSA-65 is a load-bearing demonstration that BastionVault's PQC primitives aren't just theoretical -- they sign the very documents that prove the system is operating correctly.

## Current State

- **No compliance subsystem exists.** The closest analogue is the audit log, which ships JSONL events through the existing audit broadcasters. Operators have to roll their own queries.
- **State that's already auditable** (i.e. data the new subsystem can query without any extra capture work):
  - Audit events -- per-request bodies with HMAC redaction (see CLAUDE.md "audit-logging" feature).
  - Mount table + per-mount config (`MountTable`, `MountsRouter`).
  - Policy storage (`src/modules/policy/`).
  - Identity entities, aliases, groups (`src/modules/identity/`).
  - Lease metadata (the lease manager).
  - Seal config + barrier metadata.
- **State that doesn't yet exist but is needed for some controls**:
  - **Configuration baseline snapshots** (point-in-time captures of mount + policy + identity state) -- needed for "configuration management" and "change tracking" controls. Phase 2 adds these.
  - **Access reviews** (periodic confirmation that each entity still needs the access it has) -- some controls require *evidence of review*, not just *evidence of access*. Phase 3 adds a lightweight access-review workflow.
- The audit redaction model (HMAC per audit-device key) is **load-bearing** for compliance reporting: it lets a report assert "user X accessed path Y" without leaking Y's value, which is what most auditors actually want.

## Design

### Frameworks Targeted in v1

| Framework | Scope | Controls covered v1 |
|---|---|---|
| **SOC 2** (Trust Services Criteria, 2017 + 2022 points-of-focus) | CC6.1–CC6.8 (Logical & Physical Access), CC7.1–CC7.4 (System Operations), CC8.1 (Change Management). Some CC2/CC3/CC4 governance controls are *partially* mappable (we can produce evidence; we cannot attest to your governance program). | ~22 controls |
| **ISO/IEC 27001:2022 Annex A** | A.5.15, A.5.16, A.5.17, A.5.18 (access control), A.8.2, A.8.3 (privileged access, identity), A.8.15, A.8.16 (logging, monitoring), A.8.24 (cryptography). | ~18 controls |
| **PCI-DSS v4.0** | Requirement 3 (cryptography of stored data), 7 (least privilege), 8 (identity), 10 (logging). | ~14 sub-requirements |
| **HIPAA Security Rule** | §164.308(a)(3), §164.308(a)(4) (access management), §164.312(a)–(c) (technical safeguards), §164.312(b) (audit controls). | ~9 sub-controls |
| **NIST SP 800-53 rev 5** (Moderate baseline) | AC-2, AC-3, AC-6, AU-2, AU-3, AU-6, AU-12, IA-2, IA-5, SC-12, SC-13, SC-28. | ~12 controls |
| **LGPD / GDPR** | LGPD Art. 37 (record of processing), Art. 46 (security measures); GDPR Art. 30 (records), Art. 32 (security), Art. 33 (breach detection signals). Outputs are tailored to "show me access to PII-scoped paths" + "the security measures we've implemented." | ~6 articles |

For each control we ship a **mapping document** (`control_mappings/<framework>/<control>.md`) that explains:
- The control text (paraphrased; not the verbatim copyrighted text).
- The exact query/queries the report runs.
- The interpretation of the result ("absence of denial events for this path = evidence of preventive control effectiveness").
- Known limitations (which sub-points the report does *not* cover and why).

### Layer 1 -- Query API

```
POST /v1/compliance/query
{
  "select": ["request_id", "actor.entity_id", "path", "operation"],
  "from":   "audit_events",
  "where":  {
    "time_range":  { "start": "2026-01-01T00:00:00Z", "end": "2026-03-31T23:59:59Z" },
    "operation":   ["read", "write", "delete"],
    "path_glob":   "secret/prod/*",
    "outcome":     ["success", "denied"]
  },
  "group_by": ["actor.entity_id", "operation"],
  "limit":    10000
}
```

The query language is a deliberately small JSON subset -- not SQL -- because:

- Auditors and GRC tools want **predictable structure**, not flexibility.
- Restricting the surface lets the framework produce a stable schema we can version (`schema_version: 1`) and let downstream tools depend on.
- We can index audit events for the small set of fields the language exposes (`time_range`, `actor.entity_id`, `path_glob`, `operation`, `outcome`, `mount`) without committing to a full query planner.

Available `from` sources:

- `audit_events` -- the audit log.
- `mounts` -- the mount table at query time, or at a snapshot timestamp.
- `policies` -- policy documents at a snapshot.
- `entities`, `aliases`, `groups` -- identity state at a snapshot.
- `leases` -- live + revoked-within-window lease metadata.
- `config_snapshots` -- the snapshots from Phase 2.

Each `from` declares a frozen field schema; the schemas are documented in `docs/docs/compliance/query-schemas.md`.

### Layer 2 -- Pre-built Reports

```
GET /v1/compliance/reports/<framework>/<control>?start=...&end=...
```

Each report is a small Rust function that:
1. Composes one or more `compliance/query` calls under the hood.
2. Joins / aggregates / annotates the results.
3. Emits a stable JSON schema specific to that control.

Example: `GET /v1/compliance/reports/soc2/CC6.1?start=2026-01-01&end=2026-03-31` returns:

```json
{
  "control": "CC6.1",
  "framework": "soc2",
  "framework_version": "2017+2022",
  "window": { "start": "...", "end": "..." },
  "schema_version": 1,
  "summary": {
    "total_access_events": 184_220,
    "denied_events": 47,
    "unique_actors": 38,
    "privileged_actors": 4,
    "mounts_in_scope": 12
  },
  "evidence": [
    { "kind": "policy_inventory",     "ref": "/v1/compliance/query/...inline..." },
    { "kind": "denial_sample",        "events": [...] },
    { "kind": "privileged_access_log", "events": [...] },
    { "kind": "mount_inventory",      "snapshot": "..." }
  ],
  "control_mapping_doc": "control_mappings/soc2/CC6.1.md",
  "generated_at": "2026-04-25T12:00:00Z",
  "generated_by": { "entity_id": "...", "display_name": "..." }
}
```

The schema is **stable across runs** (sort orders are deterministic, generation timestamps are pulled out into a clearly-marked `generated_at` field) so two reports produced by two different operators on the same window over the same data should diff at zero -- a property auditors love.

A meta-endpoint `GET /v1/compliance/reports/<framework>` returns the **bundle**: every control under that framework in one call, at the cost of a longer-running query.

### Layer 3 -- Signed Evidence Packages (`.bvev`)

```
POST /v1/compliance/export
{
  "framework":     "soc2",
  "controls":      ["CC6.1", "CC6.2", "CC6.3", "CC7.1"],
  "window":        { "start": "...", "end": "..." },
  "include_audit_raw": false,
  "signing_key":   "compliance-evidence-key"
}
```

Returns a download token; `GET /v1/compliance/export/<token>` streams a `.bvev` file with this layout (deterministic JSON throughout, sorted keys, LF line endings, no trailing whitespace):

```
manifest.json                       # bundle metadata: framework, controls, window, generator version
control_mappings/soc2/CC6.1.md      # static mapping doc, copied in
control_mappings/soc2/CC6.2.md
...
reports/soc2/CC6.1.json             # the report payload from Layer 2
reports/soc2/CC6.2.json
...
queries/<hash>.json                 # the underlying queries that fed each report (full reproducibility)
state/mounts.json                   # mount table snapshot at end of window
state/policies.json
state/identity.json
audit/                              # only if include_audit_raw=true
hmac.bin                            # HMAC-SHA-256 of the canonical concatenation of all files (Vault-compatible header)
signature.bin                       # ML-DSA-65 signature over the same canonical concatenation
public_key.pem                      # the verifier's ML-DSA-65 public key (also published at /v1/compliance/public-key)
```

The signing key (`compliance-evidence-key`) is the role-name of an ML-DSA-65 key in the **Transit engine** ([features/transit-secret-engine.md](transit-secret-engine.md)) that the operator marks as the compliance signer. This means:

- Key rotation goes through Transit's `rotate` semantics -- old packages still verify against the version they were signed with.
- The Transit policy gates who can sign evidence (typically a single high-privilege "compliance officer" entity).
- The PQC signature is a real demonstration of the BastionVault crypto stack, not a bolted-on use case.

A standalone verifier binary `bv-verify-evidence` ships in `cmd/bv-verify-evidence/` so the auditor can verify the package without needing BastionVault running. It accepts the `.bvev` and the `public_key.pem` and prints `OK` + the canonical hash, or fails with the offending file.

### Module Architecture

```
src/modules/compliance/
├── mod.rs                          -- ComplianceModule; route registration
├── backend.rs                      -- ComplianceBackend; per-query lock; cache
├── query/
│   ├── mod.rs                      -- query parser + planner
│   ├── audit_events.rs             -- audit log iterator with index
│   ├── mounts.rs                   -- mount-table source
│   ├── policies.rs
│   ├── identity.rs
│   ├── leases.rs
│   └── snapshots.rs                -- Phase 2 config-snapshot source
├── reports/
│   ├── mod.rs                      -- ReportRegistry
│   ├── soc2/
│   │   ├── cc6_1.rs ... cc8_1.rs
│   ├── iso27001/
│   │   ├── a_5_15.rs ... a_8_24.rs
│   ├── pcidss/
│   │   └── req_3.rs ... req_10.rs
│   ├── hipaa/
│   ├── nist_800_53/
│   └── lgpd_gdpr/
├── export/
│   ├── mod.rs                      -- /v1/compliance/export driver
│   ├── bvev.rs                     -- .bvev format encoder/decoder
│   └── canonical.rs                -- deterministic JSON serialiser
├── snapshots/
│   ├── mod.rs                      -- Phase 2: scheduled state snapshotting
│   └── differ.rs                   -- diff snapshot N vs snapshot N+1 for change-management reports
├── access_review/
│   ├── mod.rs                      -- Phase 3: access-review workflow
│   └── path_review.rs              -- /v1/compliance/access-reviews/*
└── path_*.rs                       -- HTTP path handlers
```

Plus:

```
cmd/bv-verify-evidence/             -- standalone .bvev verifier
control_mappings/                   -- static control mapping docs (markdown), copied into bundles
```

### Audit-Event Indexing

The audit log is JSONL today; a naive scan over a 90-day window is O(events). The compliance module maintains a **secondary index** under `compliance/index/<bucket>/<field>` keyed by `(date_bucket, field, value) -> Vec<event_id>`. Indexed fields are exactly the small set the query language exposes (`actor.entity_id`, `path_glob_prefix`, `operation`, `mount`, `outcome`). The index is rebuilt on engine start if the audit-event file's mtime is newer than the index, and is updated lazily on every audit event.

**This is not a search index; it's a point-lookup index.** It lets `WHERE actor.entity_id = "..." AND time_range = ...` short-circuit the scan to O(matching events).

### Snapshots (Phase 2)

A scheduled task (default daily at 03:00 local; configurable) snapshots:

- The mount table.
- All policies.
- All identity entities + groups.
- The seal/barrier configuration metadata.
- The token-policy assignment table.

Snapshots are barrier-encrypted and stored at `compliance/snapshots/<rfc3339-date>/`. They are append-only and retained per a configurable retention policy (default 7 years for compliance reasons). A diff between consecutive snapshots feeds the **change-management** reports (SOC 2 CC8.1, ISO 27001 A.8.32, NIST 800-53 CM-3) -- "every config change in the audit window, who made it, what it was."

### Access Reviews (Phase 3)

Some controls (NIST 800-53 AC-2(1), ISO 27001 A.5.18, SOC 2 CC6.2) require *evidence that someone reviewed access* -- not just that the access existed.

A new lightweight workflow:

```
POST /v1/compliance/access-reviews                  # start a review cycle
GET  /v1/compliance/access-reviews/:id              # fetch
POST /v1/compliance/access-reviews/:id/decisions    # reviewer marks each entity-policy pair as Keep / Revoke / Reduce
POST /v1/compliance/access-reviews/:id/close        # close the review; emits an audit event + a frozen evidence record
```

Reviews are first-class objects with their own audit trail; closed reviews are immutable (tagged `closed` in the storage record; mutations refused).

The GUI ships an "Access Reviews" page where the compliance officer can drive a quarterly review without leaving the app.

## Implementation Scope

### Phase 1 -- Query Layer + Pre-built Reports for SOC 2 + ISO 27001

| File | Purpose |
|---|---|
| `src/modules/compliance/mod.rs` | Module + route registration. |
| `src/modules/compliance/backend.rs` | Backend wiring, query cache. |
| `src/modules/compliance/query/*` | Query parser, planner, and per-source iterators (audit_events, mounts, policies, identity, leases). |
| `src/modules/compliance/reports/soc2/*` | CC6.1–CC6.8, CC7.1–CC7.4, CC8.1. |
| `src/modules/compliance/reports/iso27001/*` | A.5.15, A.5.16, A.5.17, A.5.18, A.8.2, A.8.3, A.8.15, A.8.16, A.8.24. |
| `control_mappings/soc2/*.md`, `control_mappings/iso27001/*.md` | Static mapping docs. |

Dependencies: none new. Reuses `serde_json`, `chrono`, `glob` (already in tree).

### Phase 2 -- PCI-DSS, HIPAA, NIST 800-53, LGPD/GDPR + Snapshots

| File | Purpose |
|---|---|
| `src/modules/compliance/snapshots/*` | Daily snapshotter + diff engine. |
| `src/modules/compliance/reports/pcidss/*` | Req 3, 7, 8, 10. |
| `src/modules/compliance/reports/hipaa/*` | §164.308 / §164.312 sub-controls. |
| `src/modules/compliance/reports/nist_800_53/*` | AC-2/3/6, AU-2/3/6/12, IA-2/5, SC-12/13/28. |
| `src/modules/compliance/reports/lgpd_gdpr/*` | LGPD 37, 46; GDPR 30, 32, 33. |
| `control_mappings/pcidss/*.md`, etc. | |

### Phase 3 -- Signed Evidence Export + Access Reviews

| File | Purpose |
|---|---|
| `src/modules/compliance/export/*` | `.bvev` encoder + `canonical.rs` deterministic JSON. |
| `src/modules/compliance/access_review/*` | Review workflow. |
| `cmd/bv-verify-evidence/main.rs` | Standalone verifier binary. |

Dependencies:

```toml
zip       = { version = "2", default-features = false, features = ["deflate"] }   # .bvev container
hmac      = "0.12"   # already transitively present
sha2      = "0.10"   # already present
fips204   = "0.4.6"  # already present (PQC signing via Transit)
```

### Phase 4 -- GUI Integration

| File | Purpose |
|---|---|
| `gui/src/routes/CompliancePage.tsx` | New top-level page; framework picker, control list, report viewer. |
| `gui/src/components/ReportViewer.tsx` | Renders the JSON report into a human-friendly summary + drill-down. |
| `gui/src/components/EvidenceExportModal.tsx` | Window picker + control multiselect + signing-key picker; downloads the `.bvev`. |
| `gui/src/routes/AccessReviewPage.tsx` | Review-cycle workflow UI. |

### Not In Scope

- **Continuous compliance monitoring / alerting** ("page the on-call when a denial event hits CC6.1 evidence"). Tracked separately as a future "Compliance Alerting" feature; the building block is the same query layer.
- **Auditor portal** (a separate authenticated UI for external auditors to log in and download evidence directly). Customers vary too widely on auditor-trust models; the signed `.bvev` export is a more flexible primitive.
- **Cross-vault aggregation** (one report spanning multiple BastionVault instances). Each instance exports its own `.bvev`; aggregation is a GRC platform's job.
- **Verbatim copyrighted control text** in the mapping docs. We paraphrase + cite. Ingesting the verbatim ISO text would be a licensing problem.
- **Custom-framework support** ("our internal control catalogue"). The query layer is enough for customers to write their own reports; we don't ship a framework-authoring DSL in v1.
- **PII-scope auto-discovery**. LGPD/GDPR reports require operators to tag mounts/paths as PII-scoped via a mount-config flag (`pii_scope = true`); we don't auto-classify content.

## Testing Requirements

### Unit Tests

- Query parser: every JSON shape in the docs round-trips through parse/serialise.
- Query planner: a query with `actor.entity_id` filter uses the index; without it falls back to full scan and emits a `slow_query` warning event.
- Each Phase 1 report: feed a fixed, hand-built audit-event fixture, assert the report JSON matches a golden file byte-for-byte. Golden files live in `tests/compliance/golden/<framework>/<control>.json`.
- `.bvev` canonical-JSON encoder: same Rust struct -> same bytes across two runs (determinism test).
- HMAC + ML-DSA-65 signing roundtrip: encode, sign, verify with `bv-verify-evidence` -- pass; flip one byte in a report file -- verifier rejects.

### Integration Tests

- Spin up a vault, generate a synthetic 90-day audit log via a load harness, run `GET /v1/compliance/reports/soc2`, confirm: (a) all controls populate, (b) the report bundle is reproducible (run it twice, diff = 0 except generation timestamp).
- Snapshot diffing: snapshot at T0, mutate the mount table, snapshot at T1, run the change-management report, confirm exactly the mutation shows up.
- Export a `.bvev` for a 30-day window, hand the file + public key to `bv-verify-evidence`, confirm `OK`. Tamper one byte in `reports/soc2/CC6.1.json`, re-verify, confirm rejection with the offending path printed.
- Access review: open a review, mark 50 entity-policy pairs (mix of Keep/Revoke/Reduce), close, confirm the closed evidence record matches the decisions and is immutable.

### Cucumber BDD Scenarios

- Compliance officer opens the GUI, picks "SOC 2", picks the audit-window date range, clicks "Generate Evidence Bundle"; gets a `.bvev` download. The auditor verifies offline with `bv-verify-evidence`.
- Auditor asks "show me every privileged-access event for the engineering team in March." Officer runs the corresponding query; results match a hand-crafted reference query against the same data.
- Quarterly access review: officer kicks off a review, makes decisions, closes; the close event appears in the next compliance report's CC6.2 evidence section.

### Negative Tests

- Query with an unknown field: rejected with `field 'foo' not in schema for 'audit_events'` (no silent ignore).
- Query window > 13 months: rejected unless `allow_long_window = true` is set on the engine config (long windows have real cost; we don't want a default footgun).
- `.bvev` export with `signing_key` referring to a non-existent Transit key: rejected.
- `.bvev` export against a Transit key that is not ML-DSA-65: rejected (we want PQC signatures on evidence; classical signers are explicitly refused for this path).

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`**: same constraint as every other module. CI must fail if either becomes reachable.
- **Read-only by construction**: the compliance module never holds write capabilities on storage paths outside its own prefix (`compliance/index/`, `compliance/snapshots/`, `compliance/reviews/`). All `from` sources are read-through to the underlying authoritative state -- the module never caches state and serves stale.
- **Audit-event redaction is preserved**: the query layer cannot "unredact" HMAC'd fields. A query that asks for `path` returns the *redacted form* the audit log holds, not a reconstructed plaintext path. This matters because compliance reports may flow to third parties (auditors) who shouldn't see secret paths.
- **Snapshot protection**: snapshots are barrier-encrypted at rest. Their existence + retention is itself an audit signal -- snapshot creation/deletion events go through the standard audit pipeline.
- **`.bvev` integrity**: bundles carry both an HMAC (anyone with the audit HMAC key can verify origin within the org) and an ML-DSA-65 signature (anyone with the public key can verify *non-repudiation*). The HMAC is for ops; the signature is for auditors.
- **`.bvev` confidentiality**: bundles are **not encrypted by default**. They contain redacted audit data, summary counts, and policy/mount metadata. If a customer's threat model treats those as sensitive, they wrap the bundle with the Transit `encrypt` endpoint before transmission. We don't double-encrypt by default because the most common consumer is an auditor who has to decrypt anyway.
- **Signing-key privilege**: the Transit key used for evidence signing should be policy-restricted to a single "compliance officer" entity. The compliance module refuses to sign with a key whose Transit policy permits `update` or `delete` from any entity that also has `read` on `audit/*` (a separation-of-duties check).
- **Access-review immutability**: closed reviews are tagged `closed` and the storage record refuses subsequent writes. The audit pipeline records every decision plus the close event with the reviewer's entity id.
- **Query DoS protection**: queries have a 10-second default timeout, a `limit` cap of 100k rows, and a per-token rate limit of 10 concurrent queries. Long-window snapshots / bundles run as **background jobs** with a polling token; the API never blocks for minutes synchronously.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md), and this file's "Current State" / phase markers.
