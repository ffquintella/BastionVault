# Feature: Machine Authentication

## Summary

A new auth method for **client → remote-server** deployments of BastionVault, where a long-lived headless client (a CI runner, an agent on an operator workstation, a service account on a host) needs to authenticate to a remote `bvault` server **as a machine**, not as a human.

Each client identifies itself with a **composite key** composed of two halves:

1. A **random part** — 32 bytes generated locally at first run with `OsRng`, stored on the client (`~/.config/bvault/machine.random`, mode `0600`; on Windows, ACL'd to the current user).
2. A **host-hardware-bound part** — a stable fingerprint derived from the *physical machine the client runs on* (CPU id, total RAM, system / motherboard serial, primary disk serial, primary NIC MAC, OS kernel architecture, canonical hostname). The fingerprint is recomputed on every login by reading the same identifiers from the host; an identical machine produces an identical fingerprint, a different machine produces a different one.

Neither half is sufficient on its own:
- A stolen `machine.random` file moved to **a different host** produces a different fingerprint and the login is rejected — the random part is **bound to the specific physical machine** that enrolled.
- A clone of the host without the random part can't impersonate this client — the random part is required to derive the login proof.

Before any real operation is permitted, an **administrator must approve the enrolment request** out-of-band. Until approval, the client is `pending` and every API call other than the enrolment status poll returns `403 enrolment_pending`. Approval is performed either with a new CLI subcommand on the server (`bvault machine-auth approve <id>`) or from the admin GUI's *Auth → Machines* page.

This is **not** a replacement for AppRole, Certificate, or FIDO2. It targets a specific gap: long-lived clients on remote hosts that today either share an AppRole `secret_id` (no host-binding, single revocation surface) or run with a static token (worse).

## Security model — what this does and doesn't protect

Host-hardware fingerprinting is **not** a hardware-attested credential the way a YubiKey or TPM is. There is no signing key embedded in the silicon; the fingerprint is just a stable identifier readable by any process with sufficient privilege on the host. Be honest about what that buys:

**Protects against**
- **Random-part exfiltration to a different host.** An attacker who copies `machine.random` to their own laptop / VM / cloud instance recomputes a *different* fingerprint there → login fails. This is the primary threat we're closing: it makes the on-disk credential file useless on its own, and useless on every host except the one that enrolled.
- **Lateral movement.** Compromising a *different* machine on the same network doesn't give the attacker a working credential — they'd also need to physically be on the original host.
- **Bulk credential theft from backups.** A backup tarball that contains `~/.config/bvault/machine.random` is, on its own, not enough to authenticate anywhere.

**Does NOT protect against**
- **Local privileged compromise.** An attacker with `root` / `Administrator` on the *same* host can read `machine.random` *and* recompute the fingerprint. They get a working credential. Mitigation: short token TTLs, admin revocation, audit alerting on `machine.login` from unexpected source IPs.
- **Full machine clone (image-level VM clone).** A bit-for-bit VM image clone reproduces the disk serial, the SMBIOS serial, and the MAC; it's indistinguishable from the original. Mitigation: virtualisation platforms can change MAC + UUID on clone (libvirt / VMware), but operators must **opt in** — the doc explicitly calls this out.
- **Hardware swaps that change a fingerprint component.** Replacing a failed disk or NIC changes the fingerprint and breaks the client. The intentional choice (see *Fingerprint stability* below) is to fail-closed: if the fingerprint changes, login fails and the operator must re-enrol. We do **not** silently accept "close enough" matches.

For deployments that need stronger non-export guarantees (a hardware-rooted credential that can't be read even by `root`), the optional **TPM 2.0** path (Phase 4) re-uses the same overall workflow but anchors the hardware-bound part in a TPM-resident primary key whose private material never leaves the chip. Operators with that requirement enable it via the `tpm` build feature and pick `--hardware-backend tpm` at `init` time. Host-fingerprint is the default backend; TPM is the harder-bound upgrade.

## Motivation

- **AppRole shares a secret across the wire.** AppRole's `secret_id` is a bearer token: anyone with a copy of it can authenticate as the role until it expires. A leak is hard to detect and the only fix is rotation. Machine Authentication makes the on-disk artefact **non-portable**: a stolen `machine.random` is useless on any host except the one that enrolled.
- **Token / certificate auth doesn't bind to physical hardware.** A vault-issued client cert lives on disk; copy the file, copy the identity. Pinning the credential's *usable* form to a specific host fingerprint means the on-disk file is inert without the physical machine.
- **No human-in-the-loop today for new client trust.** Today a new client is trusted because someone handed it a working `secret_id`. There's no admin-side approval gate where an operator says *"yes, this enrolment came from the host I was expecting."* Machine Authentication adds that gate, modelled after the SSH server's host-key TOFU + admin-approve workflow operators already understand.
- **Asymmetric posture between operator and machine auth.** Operators get hardware-bound auth via the [FIDO2 / WebAuthn](audit-logging.md) flow. Machines today get a bearer secret. This feature closes the gap to whatever extent the host's hardware allows — host-fingerprint by default, TPM-rooted on supported hosts.

## Current State

- BastionVault ships [Token](../src/auth/token), [UserPass](../src/auth/userpass), [AppRole](../src/auth/approle), [Certificate](../src/auth/cert), and [FIDO2 / WebAuthn](../src/auth/fido2) auth methods. None binds a credential to the host it runs on.
- The PKI engine can issue both classical and ML-DSA / hybrid certs — Machine Authentication's signing keys ride on existing PQC primitives (Ed25519 / ML-DSA-65) for challenge / response.
- There is **no client-side state machine today** for *"this client has enrolled but is awaiting approval."* That state machine is new.

## Composite key construction

### Random part

- 32 bytes from `OsRng` at first `init`.
- Stored at `~/.config/bvault/<server-name>/machine.random` (POSIX mode `0600`; Windows ACL: deny everyone except current user + SYSTEM).
- Never sent to the server. The server only sees a *commitment*: `BLAKE3(random_part || fingerprint)`.

### Host-hardware fingerprint

A stable byte string derived from a fixed list of host identifiers, hashed with BLAKE3. Each component is read once at `init` and **once per login** (recomputed live, never cached on disk after init for verification).

| # | Component | Source (Linux / macOS / Windows) | Notes |
|---|---|---|---|
| 1 | **CPU model + vendor + family/model/stepping** | x86: `CPUID` leaf 0/1; aarch64: `MIDR_EL1` via `/proc/cpuinfo` or `sysctl hw.model` | Stable across reboots. Identical CPUs in the same SKU collide on this alone — that's why it's combined with the rest. |
| 2 | **Total RAM** | Linux `/proc/meminfo MemTotal`; macOS `sysctl hw.memsize`; Windows `GlobalMemoryStatusEx` | Rounded down to **GiB bucket** (e.g. 31.7 GiB → 31 GiB) so kernel reservations don't drift the value across kernel upgrades. |
| 3 | **Motherboard / system UUID** | SMBIOS / DMI table 1: System UUID. Linux `/sys/class/dmi/id/product_uuid`; macOS `IOPlatformUUID`; Windows `Win32_ComputerSystemProduct.UUID` | Strongest stable id on most hosts. May be `00000000-...` on cloud VMs — the algorithm degrades gracefully (see *Fingerprint stability*). |
| 4 | **Motherboard / system serial** | SMBIOS table 1: Serial Number | Useful tie-breaker when the UUID is zeroed. |
| 5 | **Primary boot disk serial** | Linux `/sys/block/<root>/device/serial` or `lsblk -no SERIAL`; macOS `diskutil info`; Windows `Win32_DiskDrive.SerialNumber` | Boot disk only; non-boot disks ignored so adding/removing data drives doesn't break the client. |
| 6 | **Primary physical NIC MAC** | First non-loopback, non-virtual interface as ranked by the OS. Filters out `docker*`, `veth*`, `vmnet*`, `tap*`, etc. | The "primary" interface is selected deterministically (lowest-index physical NIC); the rule is documented so operators can predict it. |
| 7 | **OS kernel architecture** | `uname -m` / `RtlGetVersion` | Stable; included so a 32-bit and 64-bit boot of the same hardware are distinct. |
| 8 | **Canonical hostname** | `gethostname` then `getaddrinfo` for the FQDN | Operators on machines that rename can drift here; rotation flow handles it. |

The fingerprint is computed as:

```
fp_input  = "BV-MACH-FP-v1\x00" || cpu || "\x00" || ram_gib_le8 || "\x00"
            || mb_uuid || "\x00" || mb_serial || "\x00" || disk_serial || "\x00"
            || nic_mac || "\x00" || arch || "\x00" || hostname
fp_bytes  = BLAKE3(fp_input)         // 32 bytes
```

### Composite proof at login

```
challenge       = server_random[32]                            (returned by /login)
fp_bytes        = recompute on the host every time
keyed_hkdf_in   = random_part || fp_bytes
proof           = HKDF-SHA256(keyed_hkdf_in, info=challenge, len=32)
```

Server stores `commitment = BLAKE3(random_part || fp_bytes)` registered at enrolment. To verify a login the server:

1. Sends a fresh challenge.
2. Receives `proof`, plus the *recomputed fingerprint hash* `fp_bytes_now` from the client.
3. Recomputes `expected_commitment = BLAKE3(random_part || fp_bytes_now)` — wait, the server doesn't have `random_part`. So:
4. The server stores `commitment = BLAKE3(random_part || fp_bytes)` and the client sends `fp_bytes_now` along with `proof`. The server checks **two** things:
   - `BLAKE3(client.random_part_revealed_in_proof || fp_bytes_now) == stored_commitment` — but the random part isn't revealed.
   - **Correct construction**: enrolment also registers a per-client signing keypair; the public key sits next to the commitment. At login, the client signs `(challenge || fp_bytes_now)` with the keypair's private key, where the **private key is `HKDF(random_part, "sign-v1")`**. The server verifies the signature against the registered public key, and additionally checks that `fp_bytes_now` matches the `fingerprint_commitment` stored at enrolment.

The *real* protocol therefore is:

```
ENROL
  random_part           ← OsRng[32]
  fp_bytes              ← compute_fingerprint()
  sign_priv             ← HKDF(random_part, "BV-MACH-sign-v1", len=32)   (Ed25519 seed)
  sign_pub              ← Ed25519 derive(sign_priv)
  fingerprint_commit    ← BLAKE3(fp_bytes)
  → server stores {sign_pub, fingerprint_commit}, returns enrolment_id

LOGIN
  challenge             ← /login (step 1) returns 32 random bytes
  fp_bytes              ← recompute_fingerprint()
  signature             ← Ed25519_sign(sign_priv, challenge || fp_bytes)
  → /login (step 2) {enrolment_id, fp_bytes, signature}
  server verifies:
    BLAKE3(fp_bytes) == fingerprint_commit              (host bind)
    Ed25519_verify(sign_pub, challenge || fp_bytes, signature)  (random-part bind)
  on success → mint client_token bound to approved policies
```

Both halves are required: the signature can only be produced with knowledge of `random_part` (since `sign_priv = HKDF(random_part, …)`), and the fingerprint must match the host that enrolled.

### Fingerprint stability

- Components 3 (system UUID) and 5 (boot disk serial) are the highest-entropy. If both are present and stable, components 6 (NIC MAC) and 8 (hostname) can drift one-at-a-time without breaking login — the algorithm computes a "tier-1" fingerprint from {1,2,3,4,5,7} and a "tier-2" from all eight; **server stores both commitments**. Login succeeds if either matches. A drift in tier-2 alone emits a `machine.login.fingerprint_drift` audit event so operators can spot machines that are mutating.
- If both system UUID and disk serial are missing (some bare-metal containers, some cloud instances), enrolment refuses with `fingerprint_too_weak` and the operator falls back to TPM (Phase 4) or AppRole. We don't try to soldier on with a low-entropy fingerprint pretending to be strong.
- Hardware swaps (failed disk, replaced NIC) intentionally fail-closed. The recovery path is `bvault machine-auth rotate` (re-enrol with a fresh random part *on the new hardware* — same client_id, admin re-approves, history preserved).
- Cloud VM clones / templated VMs: operators must change the SMBIOS UUID on clone (`virsh edit`, vSphere "instance UUID", AWS / Azure metadata-service UUID) — explicitly documented in the operator guide.

## Scope

### In scope (server side)

- **New auth backend** — mounted at `auth/machine/` (configurable). Routes:
  - `POST auth/machine/enrol` — client submits `{client_name, hostname, sign_pub, fingerprint_commit_tier1, fingerprint_commit_tier2, hardware_backend}`. Returns `{enrolment_id, status: "pending"}`. Idempotent on `(client_name, hostname)` — re-submitting overwrites a prior pending entry; an already-`approved` entry is locked and a re-enrol is rejected with `409 already_approved` (operator must explicitly *revoke* first).
  - `GET auth/machine/enrolment/{id}` — poll for status. Authenticated only by knowledge of the id (high-entropy token returned at enrol). Returns `{status, approved_at, approver, ttl_seconds, login_url}` once approved.
  - `POST auth/machine/login` — two-step: step 1 returns a challenge; step 2 submits `{enrolment_id, fp_bytes, signature}`. Server verifies the fingerprint commitment + the Ed25519 signature, mints a token bound to the client's approved policies, returns `{client_token, lease_duration, accessor}`. Renewable like any other Vault token.
  - `LIST auth/machine/clients` — admin-only; lists enrolled clients with status, last-seen, fingerprint summary, hardware backend, attached policies.
  - `POST auth/machine/clients/{id}/approve` — admin approves; body: `{policies: [...], ttl_seconds, max_uses?, comment?}`. Audited.
  - `POST auth/machine/clients/{id}/reject` — admin rejects with `{reason}`. Audited. Pending row moves to a `rejected` audit table; client sees `status: "rejected"` on next poll; the enrolment id is invalidated.
  - `POST auth/machine/clients/{id}/revoke` — admin revokes an already-approved client. Active tokens are immediately revoked through the lease manager.
  - `POST auth/machine/clients/{id}/rotate` — operator-driven rotation; invalidates the current `sign_pub` + commitments and accepts a fresh enrolment (same `client_id`, fresh random part + fresh fingerprint snapshot) within a TTL window. Used after a hardware swap or when the random-part on disk is suspected of disclosure.

- **Storage layout** — under the standard backend storage prefix:
  - `machine/clients/<id>` — `{name, hostname, hardware_backend, sign_pub, fingerprint_commit_tier1, fingerprint_commit_tier2, status, policies, ttl_seconds, created_at, approved_at, approver, last_login_at, last_login_ip, last_fingerprint_drift_at}`.
  - `machine/by-name/<client_name>/<hostname>` — secondary index for idempotent re-enrol.
  - `machine/audit/rejected/<id>` — append-only history of rejected enrolments.
  - All entries encrypted under the existing barrier; no new crypto.

- **Hardware backends** — selectable at `init` time, locked at approve time:
  1. **`host-fingerprint`** *(default, all platforms)* — algorithm above. No external dependencies beyond the SMBIOS / sysfs / WMI reads each platform exposes.
  2. **`tpm`** *(optional, `tpm` build feature)* — primary storage key in the platform TPM 2.0; the Ed25519 keypair *is* the TPM key, so `sign_priv` never leaves the chip. Fingerprint commit is still computed (defence-in-depth) but the TPM signature is the authoritative bind. Linux + Windows; gated behind a build feature so non-TPM hosts stay slim.

  The hardware backend is recorded on the enrolment row and locked at approve time — a client can't silently swap from `host-fingerprint` to `tpm` mid-life.

- **Policy integration** — token minted on `login` carries policies named in the approval payload. Approver can't grant policies they don't themselves hold (`sudo` policy is the existing escape hatch, same rule as for other policy-granting paths).

- **Audit events** — `machine.enrol.submitted`, `machine.enrol.approved`, `machine.enrol.rejected`, `machine.login`, `machine.login.fingerprint_drift`, `machine.token.renew`, `machine.revoke`, `machine.rotate`. Every event carries `client_id`, `client_name`, `hostname`, `hardware_backend`, `fingerprint_summary` (a non-reversible 8-char prefix of `fingerprint_commit_tier2` for human inspection), and (for approval / rejection) the actor + comment.

- **Rate limits** — `enrol` and `login` are per-source-IP rate-limited (default 10 / minute, configurable on `auth/machine/config`). A flood of `enrol` from one IP can't fill the pending queue.

### In scope (client side)

- **`bvault machine-auth init`** — interactive enrolment:
  1. Prompts for / accepts `--server <url>`, `--client-name <name>`, `--hardware-backend {host-fingerprint|tpm}` (defaults to `host-fingerprint`).
  2. Generates the 32-byte random part with `OsRng`, stores it at `~/.config/bvault/<server-name>/machine.random` (mode `0600`; Windows ACL'd to current user + SYSTEM).
  3. Computes `fp_bytes` (tier-1 + tier-2) by reading the host identifiers above.
  4. Derives `sign_priv` and `sign_pub` from the random part via HKDF.
  5. Submits `POST /auth/machine/enrol`; writes the returned `enrolment_id` next to the random part.
  6. Polls `GET /auth/machine/enrolment/{id}` every 30s with exponential backoff up to a configurable `--wait-timeout` (default 24h); exits 0 on approval, 1 on rejection.
  7. **Refuses to run on a host whose fingerprint scores below the `tier-1` threshold** (no system UUID *and* no disk serial); prints a hint to switch to TPM or AppRole.
- **`bvault machine-auth login`** — non-interactive composite-key challenge / response. Writes the resulting token to `~/.config/bvault/<server-name>/token` (or stdout for piping into other tooling). This is the command long-running services / cron jobs run.
- **`bvault machine-auth status`** — prints `{client_name, hostname, status, server_url, last_login_at, fingerprint_summary, fingerprint_drift_warning?}`. The drift warning fires when tier-1 still matches but tier-2 has changed since enrolment, so operators can spot hostname/MAC churn before it breaks something.
- **`bvault machine-auth rotate`** — regenerates the local random part *and* refreshes the fingerprint snapshot. Submits a `rotate` request signed by the *prior* keypair within a TTL window. After hardware swaps the old keypair is gone; in that case the operator runs `init` again and the admin approves a fresh enrolment.

### In scope (server-admin tooling)

- **CLI** — `bvault machine-auth list`, `bvault machine-auth approve <id> --policy default --ttl 720h`, `bvault machine-auth reject <id> --reason "unknown host"`, `bvault machine-auth revoke <id>`, `bvault machine-auth show <id>`. Same gating as the GUI (admin-only).
- **Admin GUI page** — `Settings → Auth → Machines`. Three tabs:
  - **Pending** — ranked by submission time. Each row: client_name, hostname, fingerprint summary (8-char prefix), submitted-at age, *Approve* / *Reject* buttons. Approve opens a modal that requires picking the policy set + TTL + optional comment; the policies dropdown is filtered to the operator's grant-able set. Hover on the fingerprint summary surfaces the full tier-1 + tier-2 commits in a copy-able tooltip.
  - **Approved** — searchable list with last-login, current token count, fingerprint-drift indicator (yellow dot when tier-2 has drifted since enrolment), *Revoke* button.
  - **History** — rejections + revocations + drift events, audit-style timeline.
  
  Page lives behind the existing admin policy gate (`sudo` capability on `auth/machine/clients/*`).

### Out of scope (explicit)

- **Embedded vault use.** Machine Authentication is meaningless when the client *is* the vault (Tauri GUI's embedded mode, unit tests, etc.). The auth backend refuses to mount in embedded mode and the CLI subcommands fail with `not_supported_in_embedded_vault`.
- **Replacing AppRole.** AppRole stays as the cross-platform option for environments where the host fingerprint scores too weak to be useful. Machine Authentication is additive.
- **Defending against local privileged compromise.** A `root` / `Administrator` attacker on the same host can read the random part and recompute the fingerprint; the threat model is host-binding, not local privilege isolation. TPM backend (Phase 4) closes this for hosts that have a TPM.
- **External hardware tokens (FIDO2 / PIV).** The earlier draft proposed FIDO2 / PIV as primary backends. The authoritative direction is host-hardware fingerprinting; FIDO2 / PIV are out of v1. They may return as additional backends if operator demand emerges, slotting into the same `hardware_backend` field.
- **Self-service approval.** Approval is always two-actor (the client submits, an admin approves). No auto-approve mode — that would defeat the human-in-the-loop guarantee that motivates the feature.

## Workflow Diagrams

### Enrolment

```
client                                        server                      admin
  │  bvault machine-auth init                   │                          │
  │   ├─ gen random_part (local, 0600)          │                          │
  │   ├─ read host fp components                │                          │
  │   ├─ fp_bytes = BLAKE3(fp_input)            │                          │
  │   ├─ sign_priv = HKDF(random_part, …)       │                          │
  │   ├─ sign_pub  = Ed25519(sign_priv)         │                          │
  │   └─ POST /auth/machine/enrol               │                          │
  │       {sign_pub, fp_commit_t1, fp_commit_t2}│                          │
  │ ───────────────────────────────────────────►│                          │
  │              201 {enrolment_id, pending}    │                          │
  │ ◄───────────────────────────────────────────│                          │
  │                                             │   LIST clients           │
  │                                             │ ◄────────────────────────│
  │   poll every 30s (backoff)                  │                          │
  │ ───────────────────────────────────────────►│   approve <id>           │
  │              {status: "pending"}            │ ◄────────────────────────│
  │ ◄───────────────────────────────────────────│   policies + ttl + note  │
  │                                             │                          │
  │ ───────────────────────────────────────────►│                          │
  │              {status: "approved"}           │                          │
  │ ◄───────────────────────────────────────────│                          │
```

### Login (every time the client needs a token)

```
client                                        server
  │  POST /auth/machine/login (step 1)           │
  │   {enrolment_id}                             │
  │ ───────────────────────────────────────────► │
  │              {challenge: <32B nonce>}        │
  │ ◄─────────────────────────────────────────── │
  │                                              │
  │  fp_bytes  = recompute_fingerprint()         │
  │  signature = Ed25519_sign(sign_priv,         │
  │                           challenge||fp_bytes│
  │                          )                   │
  │                                              │
  │  POST /auth/machine/login (step 2)           │
  │   {enrolment_id, fp_bytes, signature}        │
  │ ───────────────────────────────────────────► │
  │  verify BLAKE3(fp_bytes) ∈ {commit_t1,t2}    │
  │  verify Ed25519 sig over challenge||fp_bytes │
  │              {client_token, lease, accessor} │
  │ ◄─────────────────────────────────────────── │
```

## Phases

| # | Title | Notes |
|---|---|---|
| 1 | **Server backend skeleton + storage** | `auth/machine/` mount, all CRUD routes, storage layout, audit events. Login deliberately stubbed to `not_implemented` until Phase 2. Admin LIST / approve / reject / revoke / rotate routes ship here so operators can dry-run the lifecycle against a fixture client. |
| 2 | **Host-fingerprint backend (default) + client CLI** | Composite-key verification end-to-end. Cross-platform fingerprint readers (Linux sysfs/SMBIOS, macOS IOKit, Windows WMI). `bvault machine-auth init|login|status|rotate`. Server-side `bvault machine-auth approve|reject|revoke|list|show`. Integration tests against fixture hosts including the *low-entropy refusal* path. |
| 3 | **Tier-1 / tier-2 dual commitment + drift detection** | Both fingerprint commitments registered at enrol; `machine.login.fingerprint_drift` event when tier-2 changes but tier-1 holds; GUI yellow-dot on the Approved tab. |
| 4 | **TPM 2.0 backend (optional, `tpm` feature)** | Primary key + Ed25519 keypair anchored in TPM. Linux + Windows. Off by default to keep the slim build slim. |
| 5 | **Admin GUI page** | `Settings → Auth → Machines` with the three tabs above. Reuses existing admin-page chrome (pagination, search, audit-style timeline) — no new components. |
| 6 | **Token rotation + revocation polish** | Wire `rotate` end-to-end, surface "rotation pending" state in the GUI, ensure `revoke` cascades through the lease manager identically to other auth backends. |
| 7 | **Hardening + docs** | Rate limits exposed on the config endpoint, dashboard metrics (`machine_pending_total`, `machine_approved_total`, `machine_login_total`, `machine_login_drift_total`, `machine_rejected_total`), threat-model write-up under [`docs/`](../docs/), operator-facing setup guide (incl. cloud-VM clone caveats and the SMBIOS-UUID rotation recipe). |

## Open questions

- **Linux container fingerprint.** Containers on the same host share the system UUID and disk serial. Should the auth backend explicitly refuse to enrol from inside a container (detect `/.dockerenv`, `/run/.containerenv`, cgroup namespaces) and require the host operator to enrol once on the host? Leaning yes — a container-shared fingerprint defeats the whole point. Documented refusal beats silent collision.
- **macOS T2 / Apple Silicon Secure Enclave.** Apple's SE could anchor the Ed25519 key the way TPM does on PC hardware. Worth a follow-up backend, but not v1.
- **Recovery on hardware swap.** Replacing a failed disk breaks the fingerprint. Today the operator runs `init` again and the admin approves a fresh enrolment. Should we add an "emergency rotation" admin command that lets an admin re-attest a new fingerprint onto the same `client_id` so policies / token-accessor history don't get reset? Probably yes; design lands in Phase 6.
- **Multi-server topology.** A single client may need to authenticate to several BastionVault servers (multi-cluster operators). v1 keeps a 1:1 mapping (the random part lives in `~/.config/bvault/<server-name>/machine.random`); a future enhancement could share state across multiple `(server_url, client_name)` enrolments.

## Acceptance criteria

- **Phase-level**: each phase ships green CI + at least one integration test covering the happy path and the *unauthorised* path.
- **Feature-level**: a fresh client can `init` on a host with sufficient fingerprint entropy, an admin can `approve` from the CLI **or** the GUI, the client's `login` returns a token whose policies match the approval payload, and the **same `machine.random` copied to a different host fails `login` with `fingerprint_mismatch`**. Admin can `revoke` and the next `login` from that client fails with `client_revoked`. Same flow works against an HA cluster.
