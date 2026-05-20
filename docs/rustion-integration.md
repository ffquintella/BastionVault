# Rustion Bastion Integration

BastionVault can mediate every Resource Connect through a [Rustion](https://github.com/ffquintella/Rustion) bastion — a post-quantum-secure SSH/RDP/SMB proxy that records and audits every session. From the operator's point of view nothing changes: pick a resource, hit **Connect**, watch the session terminal open. Under the hood, BastionVault picks an enrolled Rustion instance, mints a signed BVRG-v1 envelope, hands the operator a single-use ticket bound to their source IP, and routes the SSH/RDP client at the bastion — never at the target directly.

Why this matters:

- **One hop, two control planes.** The bastion enforces network reachability (it's the only thing that can talk to the target subnet); the vault enforces governance (who, when, recorded how). Compromising one doesn't grant the other.
- **Recording lives off-vault.** Session recordings are written on the bastion, hash-signed, and either pushed to BV via a webhook or pulled by a 24-hour fallback poller. The vault never holds the bytes on its hot path.
- **PQC by default.** The envelope is hybrid Ed25519 + ML-DSA-65 signed and ML-KEM-768 encrypted; the bastion's TLS listener prefers post-quantum key exchange when the operator's RDP/SSH client supports it.

This page covers the day-2 operator workflow. For the protocol-level design see [`features/rustion-integration.md`](https://github.com/ffquintella/BastionVault/blob/main/features/rustion-integration.md); for the authority lifecycle (enrolment / approval / re-attestation / deenrolment) see [`features/rustion-authority-lifecycle.md`](https://github.com/ffquintella/BastionVault/blob/main/features/rustion-authority-lifecycle.md).

---

## 1. What ships in 0.8.0

| Capability                                          | Where to find it                                            |
|-----------------------------------------------------|-------------------------------------------------------------|
| Enrol a Rustion bastion                             | Settings → Rustion → Bastions, or `bvault rustion target …` |
| Connect a resource through a bastion                | Resource → Connect, transport=`rustion`                     |
| Four-tier transport + bastion policy                | Settings → Rustion Policy + per-tier editor on AGs/types    |
| Live sessions across the fleet                      | Rustion → Live Sessions                                     |
| Recordings page + in-window asciicast / RDP replay  | Rustion → Recordings → Open in window                       |
| Audit witness from the bastion's hash chain         | Auditing → Rustion audit witness                            |
| Weekly re-attestation timer                         | runs automatically; manual: `bvault rustion authority attest` |
| Clean deenrolment                                   | `bvault rustion target deenrol --id <…>`                    |
| Rustion-side approval CLI                           | `rustion authority {list-pending, approve, reject, deenrol}` |

End-to-end TLS+PQC against a Windows target needs Phase 4.2-full's CredSSP RC4 sealing — it's wire-complete and simulated-Windows tested. A live Windows VM verification pass is queued for the next available CI VM.

---

## 2. Architecture in two paragraphs

When the operator clicks **Connect** on a resource whose transport policy is `rustion`, BastionVault picks a bastion from the resource's connection profile (pinned list, ordered fallback, random pool, or bastion-group resolver). It builds a **BVRG-v1 envelope** — CBOR payload, hybrid Ed25519 + ML-DSA-65 signature, ML-KEM-768-encrypted to the bastion's KEM pubkey — and POSTs it at `https://<bastion>/v1/sessions`. The envelope carries the operator identity, source IP, target host/port, and a single-use credential the bastion will inject upstream.

Rustion verifies the envelope (authority pubkey pinned in YAML, deployment_id matches the approved record, nonce never seen, issued_at within the replay window), allocates a session id, vends a routing **ticket** (`tkt_<32 hex>`) bound to the operator's source IP, and returns it to BV. BV hands the ticket to the operator's GUI; the GUI starts an SSH/RDP client pointing at the bastion's listener. The bastion's listener inspects the ticket (SSH banner / RDP `mstshash` cookie), consumes it against its session table, dials the target with the decrypted credential, and pipes the bidirectional stream through the recorder. When the session ends the recorder signs the recording with a hybrid signature and either webhooks it to BV or holds it for the BV poller to pull.

---

## 3. Enrolling a Rustion bastion

The full operator runbook lives at [`features/rustion-authority-lifecycle.md`](https://github.com/ffquintella/BastionVault/blob/main/features/rustion-authority-lifecycle.md). Quick path:

```bash
# 1. On the BV side — export the master pubkey + deployment id.
bvault rustion master export

# 2. On the Rustion host — drop a pending YAML.
sudo tee /opt/rustion/authorities-pending/bv-prod.yaml <<EOF
schema_version: 1
name: bv-prod
pubkey_ed25519_b64: "<output from step 1>"
pubkey_mldsa65_b64: "<output from step 1>"
deployment_id: "<output from step 1>"
description: "BV prod cluster"
submitted_at: "$(date -u +%Y-%m-%dT%H:%M:%S.000000Z)"
EOF

# 3. Approve.
rustion authority list-pending
rustion authority approve --name bv-prod --max-session-secs 28800 --replay-window-secs 300
rustion reload
```

Until step 3 completes, every envelope from this BV deployment is refused with `403 authority_pending_approval`. The BV GUI's target row shows "Awaiting approval" so the operator can tell the difference from a transport failure.

### Rustion-side CLI cheatsheet

```bash
rustion authority list-pending                                      # what's waiting
rustion authority list                                              # active records
rustion authority list-tombstones                                   # rejected/deenrolled
rustion authority approve --name <n> --max-session-secs 3600
rustion authority reject --name <n> --reason "wrong deployment id"
rustion authority deenrol --name <n> --reason "asset decommissioned"
rustion authority untombstone --name <n>                            # clear a frozen name
```

### BV-side CLI cheatsheet

```bash
bvault rustion target list
bvault rustion target read --id rt_eu_1
bvault rustion target probe --id rt_eu_1                            # health probe
bvault rustion authority attest                                     # manual re-attest (all bastions)
bvault rustion authority attest --bastion-id rt_eu_1                # just one
bvault rustion target deenrol --id rt_eu_1 --reason "retired"
```

The weekly re-attestation timer runs automatically once BV starts — there is nothing to configure. It ticks every 6 days and emits `rustion.master.attest` audit rows. Manual `attest` calls land on the same audit row.

---

## 4. Connecting through a bastion

In the Resource editor:

1. Pick the resource you want to connect (an SSH or RDP target).
2. Open the **Connection profile** tab.
3. Set transport to `rustion`.
4. Pick one of the four bastion-selection modes:
   - **Pinned list** — try each bastion in order; fail if none succeed.
   - **Ordered fallback** — same as pinned but ignores any bastion the dispatcher knows is `down`.
   - **Random pool** — pick uniformly at random from healthy candidates.
   - **Bastion group** — name a bastion group; the dispatcher resolves it to the current healthy members.
5. Save.

Now any operator with the appropriate role hitting **Connect** gets routed through Rustion. The session window shows the bastion id + correlation id in the status bar so support can correlate with the bastion's audit chain.

### Forcing transport at policy time

Sometimes you want `rustion` to be the **only** transport for a class of resources — direct mode disabled even if a future operator forgets to set the profile. Use the four-tier policy ladder (resource < asset-group < type < global). Settings → Rustion Policy → Force rustion transport.

The resolver climbs the ladder bottom-up; the first explicit decision wins. A tier that's locked refuses overrides from below — handy when compliance says "PCI resources MUST go through the PCI bastion group" and you want the lock to survive resource-level edits.

---

## 5. Live sessions + recordings + audit

**Live Sessions** (Rustion → Live Sessions) polls every enrolled bastion every five seconds. The table shows operator, target, bastion, duration, recording status, and a per-row **Terminate** button. Termination sends a signed `kill` envelope to the bastion that opened the session; the session window receives a Tauri event and the bastion-side audit chain records `session.terminate`.

**Recordings** (Rustion → Recordings) lists every recording BV knows about — webhook-delivered ones land within seconds of session end, fallback-pulled ones land within 24 hours. **Open in window** spawns a separate Tauri WebviewWindow for replay:

- `asciicast` (SSH) → `asciinema`-player style scrubbing.
- `rdp-rec` (RDP) → in-tree WASM bitmap decoder rendered onto an HTML5 canvas. Uncompressed 16/24/32 bpp + RLE16/RLE24 are fully supported; NSCodec / RemoteFX / 8-bpp RLE / bitmap-cache references show in a "skipped" counter and the canvas keeps blitting later frames.
- `smb-log` (SMB) → file-operation log.

Every in-GUI playback emits a `recording.replayed` audit row with operator id + recording id + sha256 mismatch flag (the player checks integrity against the sidecar hash before rendering).

**Audit witness** — Rustion's per-bastion hash chain is pulled every minute. Every entry's signature is re-verified against the authority's pubkey before being re-witnessed into BV's chain as `rustion.audit.witness`. A tampered entry surfaces in a `tampered_audit` red banner; the chain refuses to advance past it.

---

## 6. Audit footprint

| Event                              | Side    | Fires on                                                                                       |
|------------------------------------|---------|------------------------------------------------------------------------------------------------|
| `rustion.target.enrol`             | BV      | Target record created locally                                                                  |
| `rustion.target.deenrolled`        | BV      | `bvault rustion target deenrol` succeeds                                                       |
| `rustion.master.attest`            | BV      | Weekly timer or manual attest succeeds                                                         |
| `session.open` (extended)          | BV      | Session opens; carries `transport`, `bastion_id`, `bastion_selection`, `bastion_candidates_tried`, `policy_chain`, `rustion_session_id` |
| `session.renew` / `session.terminate` | BV   | TTL extension or forced kill                                                                   |
| `session.replicated`               | BV      | Telemetry-derived from bastion's history endpoint                                              |
| `recording.linked`                 | BV      | Recording sidecar lands (webhook or pull)                                                      |
| `recording.replayed`               | BV      | In-GUI playback opens; integrity check + replay-log emitted                                    |
| `authority.approval_pending`       | Rustion | Pending YAML observed                                                                          |
| `authority.approved` / `.rejected` | Rustion | CLI approve/reject                                                                             |
| `authority.attested`               | Rustion | Verified `attest` envelope refreshes `attestation_renew_at`                                    |
| `authority.tombstoned` / `.untombstoned` | Rustion | Authority moved to/from tombstone                                                        |
| `authority.deenrolled`             | Rustion | Verified `deenrol` envelope or `rustion authority deenrol` CLI                                 |
| `authority.attestation_mismatch`   | Rustion | Envelope's `operator.deployment_id` doesn't match the pinned record                            |

The Rustion-side rows are mirrored into BV's chain as `rustion.audit.witness` after the next telemetry tick.

---

## 7. Failure modes

| Symptom (envelope HTTP) | Likely cause | Fix |
|---|---|---|
| `403 authority_pending_approval` | Bastion admin hasn't approved yet | `rustion authority approve --name <n>` + `rustion reload` |
| `403 authority_tombstoned` | Name was rejected/deenrolled before | `rustion authority untombstone --name <n>` → BV re-submits |
| `403 attestation_mismatch` | BV's `deployment_id` ≠ pinned value | Re-approve with current deployment_id, or deenrol + re-submit |
| `401 unknown_authority` | No record on this bastion | BV submits, admin approves |
| `409 envelope_replay` | Same nonce seen twice within the replay window | Almost always benign retry under load; if it persists, check system clock skew |
| `bastion_rejected_authority` (BV GUI) | All candidate bastions returned a 4xx | Read the underlying bastion error from the GUI panel; usually one of the above |
| `policy_denied` | Bastion's `allowed_targets` doesn't match the resource's host | Widen `allowed_targets` on the authority YAML or re-route via a different bastion group |
| Replay window shows "recording integrity check failed" | sha256 mismatch between sidecar and downloaded blob | Re-pull; if persistent, the bastion's storage layer needs investigation |

For deeper protocol-level troubleshooting and the original phased-rollout history, see [`features/rustion-integration.md`](https://github.com/ffquintella/BastionVault/blob/main/features/rustion-integration.md).

---

## 8. Limits + roadmap notes

- **`rdp-cert` (smart-card PKINIT)** is tracked separately; today the bastion-driven CredSSP path handles `rdp-password` only.
- **NSCodec / RemoteFX / 8-bpp RLE / bitmap-cache references** in `.rdp-rec` recordings are out-of-scope for the integration's visual replay codec; affected frames show in the "skipped" counter on the canvas player.
- **Live Windows VM transport hookup** for the CredSSP injection driver is queued for the next available CI VM. The protocol logic is wire-complete and covered by an in-process Windows responder simulator (Rustion's `tests/credssp_e2e.rs`).
- **Rustion admin web UI** — not in scope; the CLI is the supported approval interface.
- **`attestation_renew_at` enforcement** at envelope-verify time (refuse stale records with `attestation_expired`) is a one-line follow-up once the operator team picks a default expiry window. The field is recorded and the BV-side attest timer keeps it fresh; the gate is the missing piece.
