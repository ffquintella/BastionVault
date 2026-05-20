# Rustion Authority Lifecycle — Phase 9.2 deployment guide

This guide shows the day-2 enrolment workflow that ships in **BV 0.8.0 +
Rustion 0.8.0**: how an operator submits a BastionVault deployment as a
candidate authority on a Rustion bastion, how the Rustion admin
approves it, how the weekly re-attestation timer keeps it alive, and
how a clean deenrolment works at end-of-life.

Read alongside [`rustion-integration.md`](rustion-integration.md) — Phase 9.1
covers the in-memory data model, Phase 9.2 wires it to disk + the CLI.

## Directory layout

On every Rustion bastion, the on-disk authority store lives under
`$CONFIG_DIR` (default `/opt/rustion/` in release builds,
`~/.rustion/` in debug):

```
/opt/rustion/
├── authorities/               ← active, can sign envelopes
│   ├── bv-prod.yaml
│   └── bv-staging.yaml
├── authorities-pending/       ← awaiting admin approval (inert)
│   └── bv-region-eu.yaml
└── tombstoned/                ← rejected / deenrolled (frozen names)
    └── bv-old.yaml
```

All three are read by `AuthorityStore::load_from_disk(...)` at server
boot and on every `rustion reload`. The CLI (`rustion authority …`)
edits files directly under these paths and prints a reminder to
trigger `rustion reload` when the running process needs to re-read.

## YAML schemas

Schema version `1`. Future bumps are additive; the loader refuses
unknown versions with `DiskError::SchemaVersion` so you cannot
silently mis-parse a future record.

### Active authority — `authorities/<name>.yaml`

```yaml
schema_version: 1
name: bv-prod
pubkey_ed25519_b64: "Zk6JhJxQ7yK3l8...wA"
pubkey_mldsa65_b64: "MIIBCgKCAQEA...="
allowed_targets:
  - "rt_*"            # glob: every target id starting with rt_
allowed_actions:
  - open
  - renew
  - kill
max_session_secs: 28800   # 8h
replay_window_secs: 300   # ±5 min envelope freshness
revoked: false
deployment_id: "f47ac10b-58cc-4372-a567-0e02b2c3d479"
recording_webhook_url: "https://bv.prod.example/v1/rustion/webhook/recording-ready"
```

### Pending submission — `authorities-pending/<name>.yaml`

```yaml
schema_version: 1
name: bv-region-eu
pubkey_ed25519_b64: "..."
pubkey_mldsa65_b64: "..."
deployment_id: "8a3f1e2b-9c4d-4f5e-a6b7-0c8d9e0f1a2b"
description: "BV deployment at eu-west-1 submitted on 2026-05-20"
submitted_at: "2026-05-20T14:23:45.123456Z"
```

### Tombstone — `tombstoned/<name>.yaml`

```yaml
schema_version: 1
name: bv-old
deployment_id: "11111111-2222-3333-4444-555555555555"
reason: "asset decommissioned"
tombstoned_at: "2026-05-19T08:00:00.000000Z"
```

The deployment_id is *frozen* on the tombstone forever. A re-submission
that re-uses the same name is refused with `authority_tombstoned`; only
`rustion authority untombstone --name <n>` (admin action) unblocks
the name, after which the BV operator must re-submit a fresh enrolment.

## End-to-end workflow

### 1. BV exports its master pubkey + deployment id

On the BV side (operator GUI or CLI):

```bash
# Show the master pubkey + deployment id the bastion will need.
bvault rustion master export
# Output:
#   pubkey_ed25519:  Zk6JhJxQ7yK3l8...wA
#   pubkey_mldsa65:  MIIBCgKCAQEA...=
#   deployment_id:   f47ac10b-58cc-4372-a567-0e02b2c3d479
```

The deployment_id is minted on first PKI init and persists at
`sys/rustion/master/deployment-id`. It is the trust anchor that
pins the BV instance — a stolen master keypair re-used by a different
vault will fail the Phase 9.1 `deployment_id` binding check with
`403 attestation_mismatch`.

### 2. Submit the enrolment to the bastion

The BV operator (or an automation script) drops a pending YAML on
the bastion. In the simplest case, scp the file directly:

```bash
cat > /tmp/bv-prod.yaml <<EOF
schema_version: 1
name: bv-prod
pubkey_ed25519_b64: "Zk6JhJxQ7yK3l8...wA"
pubkey_mldsa65_b64: "MIIBCgKCAQEA...="
deployment_id: "f47ac10b-58cc-4372-a567-0e02b2c3d479"
description: "BV prod cluster — submitted by ops@example.com on 2026-05-20"
submitted_at: "2026-05-20T14:23:45.000000Z"
EOF

scp /tmp/bv-prod.yaml rustion-host:/opt/rustion/authorities-pending/
```

Until the bastion admin approves, **every envelope signed by this BV
returns `403 authority_pending_approval`** and the BV GUI shows the
target row as "Awaiting approval".

### 3. Rustion admin reviews + approves

On the bastion host:

```bash
# See what's waiting.
rustion authority list-pending
# NAME             DEPLOYMENT_ID                          SUBMITTED                  DESCRIPTION
# bv-prod          f47ac10b-58cc-4372-a567-0e02b2c3d479   2026-05-20 14:23:45 UTC    BV prod cluster — submitted by ops@…

# Approve with default policy (8h max session, 300s replay window).
rustion authority approve --name bv-prod

# Or tighten the policy at approval time:
rustion authority approve --name bv-prod --max-session-secs 3600 --replay-window-secs 180

# Apply the change to the running server.
rustion reload
```

The approve step moves `authorities-pending/bv-prod.yaml` → `authorities/bv-prod.yaml`,
pins the `deployment_id` on the active record, and prints the new
record's location.

### 4. Reject a bad submission

```bash
rustion authority reject --name bv-prod --reason "wrong-deployment-id provided"
rustion reload
```

The YAML moves to `tombstoned/bv-prod.yaml`. The name is now frozen.

### 5. BV side: weekly re-attestation

After BV 0.8.0 starts, a detached tokio task (`attest_timer`) ticks
every **6 days** and sends a signed `attest` envelope to every enrolled
bastion. Rustion bumps the authority record's `attestation_renew_at`
on acceptance. Failures don't short-circuit the sweep — one offline
bastion does not drop everyone else's attestation window.

Manual trigger from the GUI / CLI:

```bash
# Attest one specific bastion:
bvault rustion authority attest --bastion-id rt_eu_1

# Attest every enrolled bastion:
bvault rustion authority attest
```

Every successful attest emits a `rustion.master.attest` row to the
BV audit chain. Operators see the sweep's per-bastion outcome in the
GUI's Rustion Bastions card under "Last attest: <ts>".

### 6. Deenrolment (clean teardown)

When the operator deletes a target on the BV side, BV sends a final
`deenrol` envelope before purging the local record:

```bash
# CLI flow — sends deenrol first, then purges:
bvault rustion target deenrol --id rt_eu_1 --reason "asset decommissioned"
bvault rustion target delete --id rt_eu_1

# Or symmetrically from the bastion side, when BV is offline:
ssh rustion-host
rustion authority deenrol --name bv-prod --reason "BV deployment retired"
rustion reload
```

Either path tombstones the authority on the Rustion side. A
`rustion.target.deenrolled` audit row fires on the BV chain; the
matching `authority.deenrolled` lands on the Rustion hash chain and
gets witnessed back into BV by the Phase 8.2 audit-witness puller.

### 7. Resurrection guard

A tombstoned name cannot be re-submitted:

```bash
# (Attacker / mis-configured BV tries to re-add the same name.)
scp /tmp/bv-prod.yaml rustion-host:/opt/rustion/authorities-pending/
rustion reload
# rustion-server log:
#   authority load: authority_tombstoned (bv-prod was deenrolled on 2026-05-19)
```

To restore the name, the bastion admin must explicitly:

```bash
rustion authority untombstone --name bv-prod
# Then the BV operator re-submits a fresh enrolment (new submission
# YAML with a fresh submitted_at timestamp).
```

`untombstone` does **not** auto-promote the authority. It clears the
tombstone; the active record is rebuilt only after a new submission +
approval. The original `deployment_id` is gone from the tombstone, so
re-using the same name with a different BV instance is fine.

## Deployment recipes

### Docker compose — non-HA dev rig

```yaml
# docker-compose.yml — BV + Rustion + an OpenSSH target.
version: "3.9"
services:
  rustion:
    image: ghcr.io/your-org/rustion:0.8.0
    volumes:
      - ./rustion-config:/opt/rustion:rw   # authorities*/, tombstoned/, users/, …
    ports:
      - "2222:2222"   # SSH
      - "3389:3389"   # RDP
      - "8443:8443"   # control-plane HTTPS
    environment:
      RUST_LOG: info,rustion=debug
  bastion-vault:
    image: ghcr.io/your-org/bastion-vault:0.8.0
    volumes:
      - ./bv-data:/var/lib/bastionvault
    ports:
      - "8200:8200"
    environment:
      RUST_LOG: info
  openssh-target:
    image: linuxserver/openssh-server:latest
    ports:
      - "2200:2222"
```

Bootstrap script (run once after `docker compose up -d`):

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Get the BV master pubkey + deployment id from the bastion vault.
read PK_ED PK_ML DEP_ID < <(
  docker exec bastion-vault bvault rustion master export --format=plain
)

# 2. Drop the pending YAML on the rustion host.
docker exec rustion mkdir -p /opt/rustion/authorities-pending
docker exec -i rustion tee /opt/rustion/authorities-pending/bv-dev.yaml >/dev/null <<EOF
schema_version: 1
name: bv-dev
pubkey_ed25519_b64: "$PK_ED"
pubkey_mldsa65_b64: "$PK_ML"
deployment_id: "$DEP_ID"
description: "dev rig submitted at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
submitted_at: "$(date -u +%Y-%m-%dT%H:%M:%S.000000Z)"
EOF

# 3. Approve + reload.
docker exec rustion rustion authority approve --name bv-dev
docker exec rustion rustion reload
```

### Bare-metal — HA pair

In an HA topology (two Rustion bastions behind a load balancer for a
single BV cluster), both bastions need the **same** approved authority
record. The simplest path is to symlink the directories onto a shared
mount:

```bash
# On both rustion-1 and rustion-2:
sudo mkdir -p /shared/rustion-authorities/{active,pending,tombstoned}
sudo ln -sfn /shared/rustion-authorities/active     /opt/rustion/authorities
sudo ln -sfn /shared/rustion-authorities/pending    /opt/rustion/authorities-pending
sudo ln -sfn /shared/rustion-authorities/tombstoned /opt/rustion/tombstoned
sudo systemctl reload rustion-server
```

The CLI commands run on whichever host has the operator's shell; the
file ops land on the shared mount and both bastions pick up the
change on `rustion reload`.

### Kubernetes — pending-PR style review

Most deployments want enrolment submissions to flow through a
ChangeReview / PR gate. Pattern:

1. CI builds the pending YAML from the BV master export and proposes
   it as a PR against `infra/rustion-authorities-pending/`.
2. Reviewer merges → ArgoCD / Flux syncs the YAML into the bastion
   pod's volume.
3. A `kubectl exec rustion-0 -- rustion authority approve --name bv-prod`
   step in the post-sync hook flips the YAML over and reloads.

The CLI is intentionally idempotent: re-running `approve` against an
already-approved name is a no-op error (`not_pending`) that the
post-sync hook can ignore.

## Audit footprint

| Side     | Event                              | Fires on                                                              |
|----------|------------------------------------|-----------------------------------------------------------------------|
| BV       | `rustion.target.enrol`             | Enrolment submission record created locally                           |
| BV       | `rustion.master.attest`            | Weekly timer OR manual `attest` succeeds for one bastion              |
| BV       | `rustion.target.deenrolled`        | `bvault rustion target deenrol` succeeds                              |
| Rustion  | `authority.approval_pending`       | YAML lands under `authorities-pending/` (server reload picks it up)   |
| Rustion  | `authority.approved`               | `rustion authority approve --name <n>`                                |
| Rustion  | `authority.rejected`               | `rustion authority reject --name <n>`                                 |
| Rustion  | `authority.attested`               | Server bumps `attestation_renew_at` on a verified `attest` envelope   |
| Rustion  | `authority.deenrolled`             | Server processes a verified `deenrol` envelope                        |
| Rustion  | `authority.tombstoned`             | Either `reject` or `deenrol` produces a tombstone                     |
| Rustion  | `authority.untombstoned`           | `rustion authority untombstone --name <n>`                            |
| Rustion  | `authority.attestation_mismatch`   | Envelope's `operator.deployment_id` doesn't match the pinned record   |

The Rustion-side rows are visible to BV after the next telemetry tick
through the Phase 8.2 audit-witness puller; they re-anchor as
`rustion.audit.witness` rows on the BV chain.

## Failure-mode quick reference

| Symptom (HTTP)                                | Likely cause                                              | Operator action                                                                                       |
|-----------------------------------------------|-----------------------------------------------------------|--------------------------------------------------------------------------------------------------------|
| `403 authority_pending_approval`              | BV submitted but bastion admin hasn't approved yet         | `rustion authority list-pending` → `approve --name` → `rustion reload`                                  |
| `403 authority_tombstoned`                    | Name was rejected or deenrolled previously                 | `rustion authority untombstone --name <n>` → BV re-submits                                              |
| `401 unknown_authority`                       | No record on the bastion at all                           | BV submits fresh; admin approves                                                                       |
| `403 attestation_mismatch`                    | Envelope's `deployment_id` ≠ pinned value                  | Re-approve with the new deployment_id, OR (if expected) deenrol + re-submit                            |
| BV "Awaiting approval" never clears           | YAML lives under `authorities-pending/` but admin hasn't approved | `rustion reload` if YAML is fresh on disk; `list-pending` to confirm visibility                  |
| Attestation never refreshes (Rustion log)     | BV's attest timer is stuck OR BV → bastion network is down | `bvault rustion authority attest` (manual trigger). Check audit log for `rustion.master.attest` rows.   |

## Limitations vs the original Phase 9 spec

The following items are scoped out of Phase 9.2 and documented as
separate tracks:

- **`attestation_renew_at` enforcement at envelope-verify time.** The
  field is recorded on the `AuthorityRecord` but the verify path
  doesn't yet refuse stale records with `attestation_expired`. The CLI
  + timer + audit emission are all in place; adding the gate is a one-
  line change once the operator team picks a default expiry window.
- **Rustion admin web UI** for the approval workflow. The CLI is fully
  sufficient; a single-page admin is a Phase 7-style follow-up.
- **GUI surface for the new Tauri commands** on the BV side. The
  `rustionAuthorityAttest` and `rustionTargetDeenrol` invokables ship
  in 0.8.0; surfacing Re-attest / Deenrol buttons on the Bastions
  Settings card is an incremental UI change.
- **`rustion authority list-active` JSON output** (the human-readable
  table is in 0.8.0; a `--format=json` flag for scripted consumers
  lands later).
