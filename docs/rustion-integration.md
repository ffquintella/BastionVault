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

   Add `authority_name=<name>` if this deployment must share a bastion
   with another BastionVault. It defaults to `bastion-vault`, and the
   bastion resolves the authority record by exactly this name — two
   deployments sending the same name cannot both be trusted, because
   approving the second displaces the first. Validated as
   `[A-Za-z0-9._-]{1,64}`; changing it later invalidates every existing
   approval.

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

**Step 3 is not optional, and it does not re-run itself.** Dropping (or config-managing) a fresh pending YAML does **not** update an already-approved record of the same name — approval snapshots the pubkey into the active record, and `approve` will not overwrite a live name. So after any `master issue` / `rotate`, or after rebuilding a BV cluster, the bastion keeps verifying against the **old** pubkey and every envelope fails `401 signature_invalid` while the new key sits unread in `authorities-pending/`. Re-approve explicitly: `rustion authority list` (compare the pubkey against `bvault rustion master export`), then `rustion authority deenrol --name bastion-vault` → `rustion authority untombstone --name bastion-vault` → `rustion authority approve --name bastion-vault` → `rustion reload`.

Note also that BV presents a **fixed** authority name (`X-Rustion-Authority: bastion-vault`) and Rustion resolves the record by that name, so one bastion holds one BV slot. Two BV deployments (e.g. HML and DSV) enrolled against the same bastion overwrite each other's meaning of `bastion-vault`, and the loser gets `401 signature_invalid` — not `attestation_mismatch`, because the signature is checked before the envelope is opened and the `deployment_id` binding never gets read. Keep one BV deployment per bastion; tracked in `features/rustion-integration.md`.

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

### Connecting from inside a namespace

Rustion is a **root-namespace feature**. You enrol bastions, mint the master keypair, define bastion groups, and set the global policy tier once, at root — a child namespace never enrols its own Rustion. Selecting `rustion` transport on a resource inside a namespace therefore uses the **root-configured** fleet and the **root-issued** master cert, which is what makes it work at all: Rustion has approved exactly one BastionVault authority (pinned by pubkey + deployment id), so the envelope must be signed by root's master identity.

What *is* namespace-scoped is the credential the bastion uses to log into the target:

| | Comes from |
|---|---|
| Bastion fleet, bastion groups, global/type policy tiers, master signing cert + its PKI mount | **Root** |
| The resource, its stored secrets, and the SSH engine (`ssh/sign/<role>`) or PKI engine that issues its login credential | **The resource's own namespace** |

So a resource in `dti/esi` bound to `ssh/role=admins-esi` gets a certificate signed by `dti/esi`'s SSH CA — the CA its targets actually trust — sealed inside an envelope signed by root's master cert. Recordings follow the same split: the index is deployment-global, but a namespace only sees recordings whose target host matches one of its own resources.

Two consequences worth knowing:

- Reference the SSH mount **namespace-relative** in the connection profile (`ssh/`, not `dti/esi/ssh/`) — same convention as the direct-connect path.
- A `401 signature_invalid` on a namespaced Connect is **not** a namespace bug. The master keypair lives in the root system view and `rustion/` is header-scoped (the request path is never rewritten into `<ns>/rustion/…`), so a namespaced session/open signs with exactly the same master key a root one does. If it fails from a namespace it fails from root too — see §7 for the real cause.
- Brokering from a namespace currently requires a **root-bound** token (an admin using the namespace switcher). A token whose login namespace is non-root cannot be granted the root-owned `rustion/*` paths, because namespace policies may only reference their own namespace's paths. Letting namespace-bound tokens broker their own sessions is tracked as an open question in `features/rustion-integration.md`.

---

## 5. Live sessions + recordings + audit

**Live Sessions** (Rustion → Live Sessions) polls every enrolled bastion every five seconds. The table shows operator, target, bastion, duration, recording status, and a per-row **Terminate** button. Termination sends a signed `kill` envelope to the bastion that opened the session; the session window receives a Tauri event and the bastion-side audit chain records `session.terminate`.

**Recordings** (Rustion → Recordings) lists every recording BV knows about — webhook-delivered ones land within seconds of session end, fallback-pulled ones land within 24 hours. **Open in window** spawns a separate Tauri WebviewWindow for replay:

- `asciicast` (SSH) → `asciinema`-player style scrubbing.
- `rdp-rec` (RDP) → in-tree decoder rendered onto an HTML5 canvas. What renders depends on the recording's **format version** — see §5.1.
- `smb-log` (SMB) → file-operation log.

Every in-GUI playback emits a `recording.replayed` audit row with operator id + recording id + sha256 mismatch flag (the player checks integrity against the sidecar hash before rendering).

### 5.1 `.rdp-rec` format versions and what replays

A `.rdp-rec` file is `RREC` + a one-line JSON header + `(ts:u64 LE, type:u8, len:u32 LE, payload)` records that tile the file exactly. The header's `version` decides what the player can paint:

| version | geometry | `0x01` graphics | `0x07` surface updates | Replays? |
|---|---|---|---|---|
| 1 | header always says `1920x1080` — a hardcoded constant, not a measurement | an undelimited slice of the raw byte stream | — | **No.** Metadata only |
| 2 | the negotiated desktop, `0` for unknown | exactly one `TS_BITMAP_DATA` | — | Legacy wire bitmaps |
| 3 | as version 2 | as version 2 | decoded RGBA8888 pixels | **Yes** — this is where the screen is |
| 4 | as version 2 | as version 2 | as version 3 | **Yes**, plus a searchable keystroke transcript — see §5.2 |

- **Version 1 recordings never render, and that is correct.** They came from a recording tap that parsed unframed TCP chunks with a frame gate accepting about a quarter of all bytes. Forensics on three real recordings found **0 of 1779** graphics events carrying a self-consistent `TS_BITMAP_DATA`, at a median payload entropy of 7.75 bits/byte — compressed codec bytes, not pixels. The player says "metadata only, graphics undecodable" rather than showing a black canvas. Recordings made before the bastion's recording upgrade are all version 1.
- **Version 3 carries pixels, not graphics commands.** The bastion runs a full client-side graphics decode (`ironrdp` `ActiveStage` plus the EGFX pipeline over `drdynvc`, including zgfx and the RemoteFX / planar / NSCodec / progressive codecs) over a copy of the relayed stream and records the decoded pixels. **BastionVault therefore needs no RDP codec** — replay is an inflate and a blit — and the artifact stays readable years from now. A modern Windows target does not use the legacy `TS_UPDATE_BITMAP` path at all, which is why version 2's `0x01` path finds nothing on `evdc400`-class hosts.
- **`0x07` payload**: `x:u16 y:u16 w:u16 h:u16 format:u8 encoding:u8` then the data. `format = 1` is RGBA8888 — 4 bytes per pixel in R, G, B, A order, row-major, **top-down**, no row padding (not BGRA, not bottom-up). `encoding = 0` is raw, `encoding = 1` is an RFC 1950 zlib stream (not raw deflate, not gzip) that must inflate to exactly `width * height * 4` bytes. The producer stores raw when a region is under 512 bytes or compression did not shrink it, so **both encodings appear in the same file**.
- **Each `0x07` event is the coalesced dirty region** of the decoded desktop at that moment — no key-frame/delta distinction, and no full-frame event at the start. The canvas begins blank and fills in as regions arrive, at the producer's interval (default 1000 ms), so a recording is roughly 1 frame/s of dirty rectangles rather than a video stream. Showing a correct canvas at time *T* means replaying every region from the start, which is why the player offers Restart rather than a backwards seek.
- **`0x06` desktop-size events** are emitted when the negotiated desktop is learned or changes mid-session. Graphics rectangles are validated against the most recent `0x06`, falling back to the header; a `0x06` that differs from the current canvas resizes it and clears it.
- **Unknown event types are skipped by their declared `payload_len`.** That is the format's forward-compatibility contract — it is how version 3 added `0x07` without breaking older players. A file whose header version is above 3 replays what this build understands, skips the rest, and says it came from a newer bastion.

#### Recommended consumer behaviour

1. Read the header `version` **before** anything else and dispatch on it. Treat a missing or non-numeric version as version 1 (undecodable), not as the newest.
2. Treat `screen_width`/`screen_height` of `0` as "no bound available", never as a valid desktop size.
3. Validate every rectangle against the desktop in force *before* allocating pixels for it, and keep an absolute per-rectangle cap for the no-desktop-size case. A rectangle of 63426 x 63193 has been seen in the field; decoding it unchecked asks the allocator for ~16 GB.
4. Skip unknown `event_type`, `format` and `encoding` values by length and **count** them. Do not guess, and do not clamp a bad rectangle into range.
5. Require the inflated length to equal `width * height * 4` exactly. Both a short and an over-long stream are rejections — several inflate implementations truncate silently against a fixed output buffer, so size the buffer one byte past the expected length and compare.
6. Index `0x07` regions lazily. A 454 s session is ~450 regions; eagerly inflating full-desktop regions at 1920x1080x4 retains gigabytes.
7. Report *which* bucket every skipped event landed in. The counters are `uncompressed`, `rle16`, `rle24`, `surface-rgba8888` (painted) and `version-1-undecodable`, `unsupported`, `invalid-geometry`, `error`, `surface-unexpected-version`, `surface-truncated`, `surface-unknown-format`, `surface-unknown-encoding`, `surface-length-mismatch`, `surface-inflate-failed`, `keystroke-unexpected-version`, `unknown-event`. A bare "N skipped" is what made the black-canvas bug invisible for as long as it was.
8. **Do not assume `timestamp_ms` is monotonic across records.** It is, up to version 3; from version 4 it is not. See §5.2 *Ordering*. If your player asserts monotonicity, that assertion fires on a valid version-4 file. Derive a recording's duration from the *maximum* timestamp, not the last one read.

#### When a version-3 file has no graphics at all

Zero `0x01` **and** zero `0x07` events in a version-3 file is a real state, not a bug: the session's graphics could not be decoded on the bastion. The remaining known cause is **AVC420 / AVC444 (H.264) over EGFX**, which the bastion counts but does not decode (no H.264 decoder is linked). The player says "this session's graphics were not recordable" and points at the bastion, which records the reason in two places:

- a structured log event `RECORDING_GRAPHICS_CENSUS` (target `rustion::usage`), and
- when content was lost and nothing was recorded, an entry in the tamper-proof audit chain with type tag `recording_graphics_unrepresentable`, carrying `protocol`, `recorded_rectangles`, `unrepresentable_updates` and a byte-free `census` string.

That signal is **not** currently in the recording sidecar BastionVault imports — carrying it there is an open item on the Rustion roadmap — so the player names the state without inventing a cause it cannot see.

**Sidecar unchanged.** `recording_id`, `session_id`, `authority`, `format` (still `"rdp-rec"`), `size_bytes`, `started_at`, `finished_at`, `target_host`, `target_user`, `correlation_id` and the SHA-256 mean exactly what they always meant. Ingestion, the `recording.ready` webhook and the 24 h pull fallback are untouched by the version-3 work.

**Audit witness** — Rustion's per-bastion hash chain is pulled every minute. Every entry's signature is re-verified against the authority's pubkey before being re-witnessed into BV's chain as `rustion.audit.witness`. A tampered entry surfaces in a `tampered_audit` red banner; the chain refuses to advance past it.

### 5.2 `.rdp-rec` version 4 — the keystroke transcript

Version 4 puts a searchable **keystroke transcript** inside the same
`.rdp-rec`. There is **no new file, no new endpoint and no second fetch
path**: the transcript is inside the artifact BastionVault already pulls, so
it is already covered by the sidecar's `sha256` and by the existing chain of
custody. Rustion's authoritative specification is
`docs/rdp-keystroke-metadata.md`.

Everything about graphics is unchanged. A version-4 file renders its screen
byte-for-byte the same as a version-3 file with the same graphics records —
there is a regression test asserting exactly that in both the TypeScript and
the reference-crate suites.

#### Header additions

```json
{
  "version": 4,
  "keystroke_metadata": true,
  "keyboard_layout": "0x00000416",
  "keyboard_layout_source": "client_core",
  "max_reorder_ms": 2000
}
```

- `keystroke_metadata` — whether a keystroke track and trailer are present.
  **`false` does not mean nobody typed.** It means the feature was off on
  that bastion for that session. A missing key (every version ≤ 3 file) reads
  as `false`. BastionVault renders this as *"keystroke recording was not
  enabled for this session"*, never as an empty transcript.
- `keyboard_layout` — the resolved Windows KLID as a hex string, or `null`.
- `keyboard_layout_source` — `client_core` (read from the session's own
  `TS_UD_CS_CORE`), `config` (operator override) or `fallback`.
- `max_reorder_ms` — the ordering bound below. `0` when `keystroke_metadata`
  is `false`.

#### Two new records

`0x08` **text input**, one or more per keystroke run:

```
flags:u8  field_epoch:u32 LE  char_count:u16 LE  text_len:u16 LE  text[text_len]
```

`flags` bits: `0x01 REDACTED` (text withheld, `text_len == 0`, `char_count`
is the number of characters suppressed), `0x02 COMPOSED` (contains a dead-key
composition), `0x04 APPROXIMATE` (decoded through a fallback layout),
`0x08 RUN_END` (closes the run), `0x10 TRUNCATED` (hit the per-run cap). The
record's `timestamp_ms` is the run's **first** keystroke, not its last.
Non-character keys appear inside `text` as bracketed tokens — `[Enter]`,
`[Tab]`, `[Backspace]`, `[Ctrl+C]`, `[F5]`, `[Ctrl+Alt+Del]`.

`field_epoch` is a **correlation hint, not a field identity** — a
pass-through RDP proxy has no access to the remote UI's focus. BastionVault
uses it only to draw a separator between run groups, never labels it "field",
and depends on nothing about its accuracy.

`0x7F` **keystroke trailer**, always the last record, written as an ordinary
record so the file still tiles and older consumers skip it:

```
[timestamp_ms:u64 LE][0x7F][payload_len:u32 LE]
[payload:]  trailer JSON (payload_len - 8 bytes)
            record_len:u32 LE    # == 13 + payload_len
            "RKTR"
```

**Locate it by tail-seek, never by scanning.** Read the last 8 bytes, check
the `RKTR` magic, read `record_len`, seek to `EOF - record_len`, parse that
one record. That yields the entire transcript without touching a single
graphics byte, and its cost does not scale with the artifact — which is the
whole reason the footer exists. Both BastionVault readers have a test
asserting the read size is unchanged when the graphics ahead of the trailer
grow from 1 KiB to 4 MiB.

Trailer JSON carries `trailer_version`, `rebuilt`, `keyboard_layout`,
`keyboard_layout_source`, `text_decoding`, `runs[]`, `search_text`,
`text_applied` and a `census`. Per run: `t` (elapsed ms of the first
keystroke), `d` (duration), `n` (character count), `text` (`null` when
redacted), `redacted`, `reason` and `epoch`.

- `text_decoding` — `exact` (a layout table matched the session's KLID),
  `approximate` (fallback table) or `none` (captured but not decoded).
  **Anything other than `exact` raises a visible caveat in the GUI.**
- `rebuilt` — `true` when the bastion reconstructed the trailer after a crash
  rather than writing it live. A rebuilt trailer is **missing the session's
  final unclosed run**, so it is never presented as a complete transcript.
- `search_text` — the newline join of the non-redacted runs. This is the only
  field BastionVault indexes.
- `text_applied` — the same content with `[Backspace]`/`[Delete]` applied and
  other named keys stripped. **Derived and lossy.** BastionVault shows it as
  a clearly-labelled display pane and **never indexes it**; the server side
  does not even deserialize it.

#### Ordering — the one behavioural break

From version 4, **records are not monotonic in `timestamp_ms`.** `0x02` and
`0x08` records are buffered by the recorder until their run closes, so they
are written after graphics records bearing later timestamps. The disorder is
bounded and the header declares the bound in `max_reorder_ms`.

`0x01`, `0x03`, `0x06` and `0x07` remain monotonic **among themselves**, so
the video path needs no change: BastionVault's playback timeline holds only
those. What did change is that `duration_ms` is now the maximum timestamp
rather than the last one read, and that nothing anywhere asserts
monotonicity. If your own consumer does, that assertion will fire on a valid
file.

#### Degradation

| Artifact state | What BastionVault shows |
|---|---|
| Version ≤ 3 | "Keystroke recording was not enabled for this session" + the version that predates the track |
| Version 4, `keystroke_metadata: false` | "…not enabled" + that the bastion had the feature switched off. Distinguishable in the UI from an empty transcript |
| Version 4, trailer readable | The transcript, runs anchored at `t`, clickable to seek the player |
| Version 4, trailer truncated or absent | Falls back to scanning `0x08` records, yields every **completed** run, and says the transcript was recovered rather than read — missing per-run durations, the final unclosed run, and each withheld run's rule |
| `rebuilt: true` | The transcript plus a banner that it was reconstructed after a crash and is incomplete |
| `text_decoding != "exact"` | The transcript plus a banner naming the fidelity |

The `0x08` fallback is sound because a `0x08` is only ever written *after* its
run's redaction verdict, so everything in a crashed file is already
adjudicated. What is lost is the final unclosed run — the safe direction to
fail, since an un-adjudicated run is dropped rather than written unredacted.

#### How BastionVault stores and searches it

The bastion's `GET /v1/recordings/{rid}/blob` serves whole files and honours
no `Range`, so BastionVault cannot do Rustion's query-time tail read without
downloading every candidate artifact in full. It therefore reads each
transcript **once**, at index time, and persists the derived `search_text`
into the barrier-encrypted store:

- **Hot** — `rustion/recordings/<rid>` gains only counters and flags
  (`keystroke_state`, `keystroke_text`, `keystroke_chars`, `keystroke_runs`,
  `keystroke_redacted_runs`, `keystroke_decoding`, `keystroke_rebuilt`,
  `keystroke_complete`, `keystroke_indexed_at`). Every one is
  `#[serde(default)]`, so entries written before this feature decode with
  them at zero — which reads as *"not indexed yet"*, a third state distinct
  from both "not enabled" and "nothing typed".
- **Cold** — `rustion/recordings_keystrokes/<rid>` holds the runs, the
  `search_text` and the census. Read only when an operator opens or searches
  a transcript, never when listing recordings.

Indexing runs on the recordings poller's hourly tick, batched (each
recording costs one full artifact fetch), and can be forced per-recording.
The artifact's digest is verified against the sidecar's `sha256` **before**
anything is persisted; a mismatch refuses to index and reports
`digest-mismatch` rather than indexing best-effort.

#### Security rules BastionVault enforces

1. **A redacted run is never reconstructed.** It has no `0x02` scancode
   records and no per-key timestamps — the recorder drops both deliberately,
   because inter-keystroke timing is itself a password-recovery channel. No
   code path infers a redacted run's content from its neighbours, from the
   framebuffer, or from its length. It renders as a masked placeholder with
   its rule and its character count.
2. **The searchable text is derived, not trusted.** BastionVault rebuilds the
   newline join from the runs whose `redacted` flag is false rather than
   taking the producer's `search_text` on faith, so a producer bug cannot put
   withheld text into a BastionVault index. When the two disagree it keeps its
   own and records a warning on the transcript.
3. **The transcript is gated with playback, not with metadata.** A policy
   granting `rustion/recordings/+` reads sidecar metadata only; the bytes
   (`.../blob`) and the transcript (`.../keystrokes`) both sit one segment
   deeper, so `rustion/recordings/*` grants them together.
4. **No transcript text in a URL, a query string, a log line or an error.** A
   search *query* is subject to the same rule: it travels in a POST body (the
   search route is a `Write`, not a `Read`), and the audit event records that
   a search ran and how many hits it produced — never what it searched for.
5. **Reading a transcript is its own audit event.** `recording.replayed` says
   an operator watched the screen; `recording.transcript.accessed` says an
   operator read what was typed. They are separate rows.
6. **Redaction upstream is best-effort and the UI says so.** A transcript
   with no withheld runs is never presented as verified free of secrets — it
   means no redaction rule fired.

An empty search result is reported alongside how many recordings were
actually searched and how many have no transcript index yet. "No hits" over
an unindexed corpus is not a negative finding and is not shown as one.

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
| `recording.transcript.indexed`     | BV      | A `.rdp-rec` v4 keystroke transcript was read and stored. Counts, `text_decoding`, `rebuilt` — never typed text |
| `recording.transcript.accessed`    | BV      | An operator read one recording's keystroke transcript. Separate from `recording.replayed` on purpose |
| `recording.transcript.searched`    | BV      | A keystroke search ran. Records hit/scanned/unindexed counts and the query's **length** — never the query |
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
| `401 signature_invalid` (`Ed25519 signature half failed verification`) | The master pubkey this bastion pinned at approval time is **not** the one BV signs with today: the master was rotated or re-issued without re-approving it here, BV never had a PKI-issued master and minted one on the fly (serial `legacy-…`), or **another BastionVault deployment already owns this `authority_name` on that bastion** (check `rustion authority list` for a deployment_id that isn't yours — if so, give this deployment its own `authority_name` rather than approving over the other one) | Compare `bvault rustion master export` (or `GET rustion/master/pubkey`) with the pubkey on the bastion's authority record; re-approve the current pubkey there, or `rustion authority deenrol` + re-submit. BV's own error text names the serial + fingerprint it used. **Not** a namespace or token problem — the master keypair is deployment-global, so a namespaced session signs with exactly the same key a root session does |
| `409 envelope_replay` | Same nonce seen twice within the replay window | Almost always benign retry under load; if it persists, check system clock skew |
| `bastion_rejected_authority` (BV GUI) | All candidate bastions returned a 4xx | Read the underlying bastion error from the GUI panel; usually one of the above |
| `policy_denied` | Bastion's `allowed_targets` doesn't match the resource's host | Widen `allowed_targets` on the authority YAML or re-route via a different bastion group |
| Replay window shows "recording integrity check failed" | sha256 mismatch between sidecar and downloaded blob | Re-pull; if persistent, the bastion's storage layer needs investigation |

For deeper protocol-level troubleshooting and the original phased-rollout history, see [`features/rustion-integration.md`](https://github.com/ffquintella/BastionVault/blob/main/features/rustion-integration.md).

---

## 8. Limits + roadmap notes

- **`rdp-cert` (smart-card PKINIT)** is tracked separately; today the bastion-driven CredSSP path handles `rdp-password` only.
- **Version-1 `.rdp-rec` recordings never replay.** Their graphics events are raw stream slices, not pixels in any encoding (see §5.1). Only sessions recorded after the bastion's recording upgrade carry decodable graphics.
- **NSCodec / RemoteFX / 8-bpp RLE / bitmap-cache references** on the *legacy* `0x01` bitmap path are out of scope for the replay decoder; affected events show in the skip-reason breakdown. This does not limit version-3 recordings, whose `0x07` events carry pixels the bastion already decoded through those codecs.
- **AVC420 / AVC444 (H.264) over EGFX** is the one graphics path the bastion cannot represent, so those sessions record zero graphics events. The gap is on the bastion (no H.264 decoder linked), and the reason is only visible in the bastion's audit chain — the recording sidecar does not yet carry it.
- **Live Windows VM transport hookup** for the CredSSP injection driver is queued for the next available CI VM. The protocol logic is wire-complete and covered by an in-process Windows responder simulator (Rustion's `tests/credssp_e2e.rs`).
- **Rustion admin web UI** — not in scope; the CLI is the supported approval interface.
- **`attestation_renew_at` enforcement** at envelope-verify time (refuse stale records with `attestation_expired`) is a one-line follow-up once the operator team picks a default expiry window. The field is recorded and the BV-side attest timer keeps it fresh; the gate is the missing piece.
