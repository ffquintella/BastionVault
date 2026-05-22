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

The full operator runbook lives at [`features/rustion-authority-lifecycle.md`](https://github.com/ffquintella/BastionVault/blob/main/features/rustion-authority-lifecycle.md). The two-step picture is: **(3.1)** initialize the master keypair on the BV side, then **(3.2)** submit + approve the bastion enrolment.

### 3.1 Initialize the Rustion master keypair (one-time, per BV deployment)

The master is a hybrid Ed25519 + ML-DSA-65 keypair that signs every BVRG-v1 envelope BV sends to a Rustion bastion. As of **0.8.7** it is issued through the configured PKI secrets engine — there is no local keygen — so the steps below either run the bootstrap script (recommended) or wire up the PKI mount + roles by hand.

Verify state before you start:

```bash
bvault login   # populate ~/.vault-token, or export VAULT_ADDR + VAULT_TOKEN
bvault rustion master export
# If you see `Issued: false` and empty pubkeys, run the steps below.
# If you see real pubkeys + a deployment_id, you're already initialized —
# skip to §3.2.
```

#### Option A — Bootstrap script (recommended)

The script is idempotent: it inspects what's already on the server and skips any step that's done. Safe to re-run.

1. **Authenticate as a root-equivalent token** (the script needs to enable the PKI mount, generate a root, create roles, write `sys/rustion/master/config`, and call `issue`):

   ```bash
   bvault login -method=userpass username=root
   # or: export VAULT_TOKEN=<root token>; export VAULT_ADDR=https://bv:8200
   ```

2. **Run the script with defaults** (PKI mount `pki`, role names `rustion-master-ed25519` / `rustion-master-mldsa65`, 1-year leaf TTL, 10-year root TTL, 1-day rotate grace):

   ```bash
   scripts/rustion-master-bootstrap.sh
   ```

   Per-step output (each line is one ✓ check):

   ```
   ✓ PKI mount 'pki' present
   ✓ Root CA generated (BastionVault Rustion Master Root)
   ✓ Role 'rustion-master-ed25519' present
   ✓ Role 'rustion-master-mldsa65' present
   ✓ Master config written
   ✓ Master issued: serial 17:42:0a:…  not_after 2027-05-22T…Z
   ```

3. **Confirm initialization:**

   ```bash
   bvault rustion master export
   # pubkey_ed25519:  Zk6JhJxQ7yK3l8...wA
   # pubkey_mldsa65:  MIIBCgKCAQEA...=
   # deployment_id:   f47ac10b-58cc-4372-a567-0e02b2c3d479
   # Issued:          true
   ```

Overrides:

```bash
scripts/rustion-master-bootstrap.sh \
    --pki-mount pki \
    --ed25519-role rustion-master-ed25519 \
    --mldsa65-role rustion-master-mldsa65 \
    --ttl 8760h --max-ttl 87600h --root-ttl 87600h \
    --rotate-grace-secs 86400 \
    --common-name "BastionVault Rustion Master Root"

# Every flag with defaults:
scripts/rustion-master-bootstrap.sh --help
```

Exit codes: `0` success, `1` user/env error (bad flag, missing `bvault`, login missing), `2` PKI failure (a request returned an error — the offending response is printed), `3` master is already issued (informational; use `bvault rustion master rotate` to mint a new keypair instead of accidentally rotating from a CI loop).

**Running the script inside the container.** The script is shipped at `/usr/local/bin/rustion-master-bootstrap.sh` in every published image so operators don't need to copy it in by hand. It's POSIX sh (no bash dependency), and the production image ships a busybox `/bin/sh` by default — so a direct `podman exec` invocation works out of the box on both the production and `:debug` variants:

```bash
podman exec -it bastionvault /usr/local/bin/rustion-master-bootstrap.sh --help
podman exec -it bastionvault /usr/local/bin/rustion-master-bootstrap.sh \
    --pki-mount pki-rustion
```

If you built the image with `--build-arg INCLUDE_SHELL=0` (no shell inside the container — see [`features/packaging-podman-server.md`](https://github.com/ffquintella/BastionVault/blob/main/features/packaging-podman-server.md) for when you'd want that), copy the script out and run it from the host instead:

```bash
podman cp bastionvault:/usr/local/bin/rustion-master-bootstrap.sh ./rustion-master-bootstrap.sh
./rustion-master-bootstrap.sh
```

The script auto-detects an incompatible default PKI issuer (e.g. an EC or RSA root reused from another mount) and aborts before the issue step fails with `ErrPkiKeyTypeInvalid` — see §3.1 troubleshooting below.

The same flow ships in the GUI as **Settings → Rustion → Bastions → Master signing cert → Bootstrap master**. The button is only visible while the master is unissued; the wizard renders the same per-step ✓ list and leaves the modal open on failure so the operator can retry.

#### Option B — Manual path (finer control)

Use this when you already have a PKI mount you want to reuse, when you need to mint the root with custom subject fields, or when your org requires a separate change ticket per `bvault write` call.

1. **Enable the PKI mount** (skip if already mounted):

   ```bash
   bvault secrets enable --path=pki pki
   ```

2. **Generate the root CA** (skip if a root already exists at this mount):

   ```bash
   bvault write -field=certificate pki/root/generate/internal \
       common_name="BastionVault Rustion Master Root" \
       ttl=87600h > /tmp/rustion-root.pem

   bvault write pki/config/urls \
       issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
       crl_distribution_points="$VAULT_ADDR/v1/pki/crl"
   ```

3. **Create one role per algorithm.** Names are arbitrary, but they must match what step 4 references. `key_type` must be exactly `ed25519` or `ml-dsa-65`:

   ```bash
   bvault write pki/roles/rustion-master-ed25519 \
       key_type=ed25519 \
       allow_any_name=true \
       ttl=8760h \
       max_ttl=87600h

   bvault write pki/roles/rustion-master-mldsa65 \
       key_type=ml-dsa-65 \
       allow_any_name=true \
       ttl=8760h \
       max_ttl=87600h
   ```

4. **Wire the rustion master at those roles:**

   ```bash
   bvault rustion master config \
       pki_mount=pki \
       pki_role=rustion-master-ed25519 \
       pki_role_pqc=rustion-master-mldsa65 \
       issuer_ref=default \
       default_ttl_secs=31536000 \
       rotate_grace_secs=86400
   ```

   Confirm:

   ```bash
   bvault read sys/rustion/master/config
   ```

5. **Issue the hybrid master.** This calls `pki/issue/<role>` twice (once per algorithm), captures both serials + leaf-cert PEMs, and persists the keypair under the encrypted barrier view:

   ```bash
   bvault rustion master issue
   # serial:     17:42:0a:...
   # not_after:  2027-05-22T14:02:33Z
   # algorithm:  hybrid-ed25519-mldsa65
   ```

6. **Confirm initialization** (same check as Option A step 3):

   ```bash
   bvault rustion master export
   ```

Troubleshooting `bvault rustion master issue`:

| Error                                                       | Cause                                                                                                | Fix                                                                                                       |
|-------------------------------------------------------------|------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------|
| `pki_mount / pki_role / pki_role_pqc must be configured`    | Step 4 didn't run or wrote into the wrong path                                                       | Re-run `bvault rustion master config …` and verify with `bvault read sys/rustion/master/config`           |
| `master already issued; use rotate to mint a new keypair`   | Idempotency guard — a current master already exists                                                  | Run `bvault rustion master rotate` instead                                                                |
| `pki engine error: role "..." not found`                    | Role names in `master/config` don't match the PKI roles created in step 3                            | `bvault list pki/roles` and reconcile                                                                     |
| `pki engine error: unsupported key_type ...`                | Wrong `key_type` on the role                                                                         | Recreate the role with `key_type=ed25519` or `key_type=ml-dsa-65`                                         |
| `ErrPkiKeyTypeInvalid` (typically on the ML-DSA-65 half)    | The PKI mount's **default issuer is classical (EC / RSA)** — BV's PKI engine refuses to sign an ML-DSA-65 leaf with a classical root. Happens most often when the wizard / script reuses an existing PKI mount that already had a non-PQ-compatible root. | Prefer a fresh mount (see below). Otherwise, delete the incompatible issuer: `bvault delete <mount>/issuer/default` then re-run, OR promote a compatible Ed25519 issuer at this mount with `bvault write <mount>/config/issuers default=<ref>` and re-run. |

##### Why this happens and how to avoid it

The hybrid master is **Ed25519 + ML-DSA-65**. The PKI engine can sign an Ed25519 leaf from an EC / RSA / Ed25519 issuer, but it **does not** support classical → post-quantum chains: an EC or RSA root cannot sign an ML-DSA-65 leaf. The bootstrap wizard's "issuer already present → skip root generation" branch (versions ≤ 0.8.8) accepted any existing default issuer at the mount, which silently set this up to fail at the issue step five clicks later.

As of 0.8.9 the wizard now reads the default issuer's `key_type` before skipping the root step and refuses up-front with the same remediation if it sees anything other than `ed25519` / `ml-dsa-65`. The issue step also rewrites the raw `ErrPkiKeyTypeInvalid` message with a pointer at the likely culprit and the two fix paths.

**Recommended remediation when you hit this on a shared mount:**

1. Re-open the **Bootstrap Rustion master** modal in the GUI (Settings → Rustion → Bastions → Master signing cert).
2. Change the **PKI mount** field from `pki` to a fresh value like `pki-rustion`.
3. Click **Bootstrap**. The wizard mints a clean Ed25519 root at the new mount and the ML-DSA-65 leaf signs cleanly.

Or from the CLI, swap `--pki-mount pki` for `--pki-mount pki-rustion` on `scripts/rustion-master-bootstrap.sh`.

#### Rotation (after initialization)

Once issued, mint a fresh hybrid keypair anytime with:

```bash
bvault rustion master rotate
# Archives current -> previous, arms previous_grace_until = now + rotate_grace_secs,
# then mints a fresh current. BVRG-v1 envelopes signed by the outgoing
# key remain valid until the grace window closes (default 1 day).
```

### 3.2 Submit + approve the bastion enrolment

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
