# Feature: Rustion Bastion Integration

## Summary

Delegate **Resource Connect** sessions through [Rustion](/Users/felipe/Dev/Rustion) — a security-first SSH / RDP / SMB bastion with post-quantum transport and tamper-proof recording — instead of opening a direct connection from the operator's GUI host to the target. BastionVault remains the system of record for **identity, credentials, and authorization**; Rustion becomes the system of record for **transport, session lifecycle, and recording**.

The bond between the two is asymmetric and minimal:

1. **Trust anchor.** BastionVault holds a long-lived **master signing certificate** (the *Vault Operator* identity). Its public key is enrolled in Rustion once, out-of-band, as a trusted authority.
2. **Session request.** When an operator clicks Connect on a server resource and chooses the *Rustion* connection profile, BastionVault builds a **session-grant envelope** containing the just-resolved target credentials (SSH key, RDP password, ...), encrypts it to **Rustion's** public key, and signs the ciphertext with the master cert.
3. **Session creation.** Rustion verifies the signature against the enrolled trust anchor, decrypts the envelope, materialises a short-lived session bound to a TTL, and hands the operator a one-shot connection ticket (host + port + opaque session id + per-session token).
4. **Renewal.** Before the TTL expires, the GUI asks BastionVault to re-sign a renewal request. Rustion extends the existing session in place if (and only if) the renewal envelope is still signed by the same master identity and the operator's policy still permits it.
5. **Recording.** Rustion captures the session in its native formats (asciicast v3 for SSH, `.rdp-rec` for RDP). BastionVault stores **only a pointer** to the recording — never the bytes — and exposes it on the audit timeline.

Net result: operators get the same one-click Connect UX as today, but every session is mediated by a bastion that does PQC at the wire and dual-signed hash-chain audit at the edge, and the operator's workstation never holds long-lived target credentials.

## Motivation

- **PAM completeness.** Today's [Resource Connect](resource-connect.md) opens SSH / RDP from the operator's laptop straight to prod. That is fine for a small team but doesn't satisfy a regulated PAM control set: there's no recording, no centralised session termination, no network choke-point. Rustion is exactly that choke-point.
- **Recording without rebuilding it.** Session recording was explicitly out-of-scope for Resource Connect ("we may add this as a separate feature once basic Connect lands"). Rustion already ships asciicast v3 + `.rdp-rec` recording, hash-chained and dual-signed. Delegating to it lets us check that box without putting a recorder in the Tauri host.
- **Network reachability.** Operators on a corporate VPN often can't reach prod targets directly; they can reach a single bastion. Today they have to maintain a separate SSH config + jumphost flow alongside BastionVault. With Rustion-mediated Connect, BastionVault knows the bastion topology and the operator just clicks Connect.
- **Credential blast radius.** When the GUI opens a direct SSH session, the cleartext credential lives in the Tauri host's memory for the session lifetime. With Rustion-mediated Connect, the credential travels as ciphertext and is decrypted *only inside Rustion's process*; the operator's machine never decrypts it.
- **Post-quantum at the wire.** Rustion's SSH and TLS layers do hybrid X25519 + ML-KEM-768 by default. BastionVault already does PQC at rest (ChaCha20-Poly1305 barrier, ML-KEM-768 / ML-DSA-65). Pairing the two closes the gap between "secrets at rest are PQ-safe" and "the connection that carries them is PQ-safe."
- **Forced revocation.** Today there is no way for a vault admin to kill an in-progress Connect session — the SSH/RDP socket is end-to-end and the GUI is just a viewer. Rustion exposes a `terminate-session` admin command; integrating means BastionVault's "force disconnect" button has somewhere to go.

## Current State

- [Resource Connect](resource-connect.md) ships seven phases (SSH × {Secret, LDAP, PKI} ✅, RDP × {Secret, LDAP, PKI smartcard via CredSSP} ✅, ⌘K palette, per-type policy). As of Phase 7.4, the in-app Connect button consults the per-resource Rustion policy and routes both SSH-password and RDP-password sessions through a bastion when transport is `rustion-required` or `rustion`; non-password SSH under `rustion-required` still fails closed pending the SSH-broker path. As of Phase 9.5, smart-card (rdp-cert) RDP also routes through the bastion via Kerberos PKINIT / SPNEGO (the envelope carries the cert + key + PIN; Rustion drives the upstream CredSSP with an sspi smart-card identity), so it no longer fails closed on the BastionVault side — the sspi engine is build-gated (`rustion_pkinit_sspi`) and live-AD validation is pending.
- BastionVault has a [PKI engine](pki-secret-engine.md) that can issue both classical and ML-DSA / hybrid certs — the master signing cert can ride on existing PKI plumbing (no new key-management subsystem).
- BastionVault has [audit logging](audit-logging.md) (HMAC-chained file device). Pointer events to remote recordings slot into the existing pipeline.
- Rustion (`/Users/felipe/Dev/Rustion`) is its own server with its own user / target / role YAML store, its own auth (password + Argon2id, certificate, SAML, FIDO2, TOTP), and its own admin TUI. It does **not** today expose a control-plane API for "create me a session for this credential, signed by an external trust anchor." That control plane is the new surface this feature adds — symmetric work in both repos.
- There is no integration today; the two products are co-developed by the same author but ship independently.
- **Namespace-scoped recordings.** The `rustion/` mount is a single deployment-global fleet (targets + recordings live only in the root mount table), so it is header-scoped in the namespace router — a namespaced request resolves against the global mount instead of 404-ing. The `rustion/recordings` list applies per-namespace scoping in the handler: in a non-root namespace it returns only recordings whose `target_host` matches a resource (hostname/IP) in that namespace's `resources/` mount; root sees all, and recordings matching no namespace resource stay visible only at root.

## Scope

### In scope (BastionVault side)

- **Master Operator certificate** — a long-lived (default 5y) signing cert held in a new `rustion/master` slot under the PKI engine. Hybrid by default (Ed25519 + ML-DSA-65). Public half exported for one-shot enrolment in Rustion.
- **Rustion target registry — multi-instance is the default, not an optional mode.** A new top-level `rustion/` mount stores **N** Rustion instances; the integration is designed around the assumption that a real deployment runs **more than one** Rustion (per-region, per-environment, primary + DR, PCI zone vs. corporate zone, …). Each entry stores `id`, `name`, `endpoint` (host:port for the control plane), `public_key` (Rustion's hybrid pubkey, pinned per instance), `default_recording_dir` pointer, `enabled`, `tags`, `health` (see below). Targets are addressable individually, grouped into **named bastion groups** (see *Bastion-group selection* below), or drawn from at random as a global pool. There is no fixed cap on the number of enrolled instances — operators have stress-tested up to 64 in a single deployment without any architectural change required. Each Rustion instance has its **own hybrid keypair**: rotating one instance's pubkey does not invalidate the others, and removing one instance is a single registry delete (refused while it has active sessions) rather than a global re-enrolment.
- **Health monitoring** — a background task pings every enabled Rustion target on a configurable interval (default 30s) and stores `health = { status: "up" | "degraded" | "down" | "unknown", last_ok_at, last_error, latency_ms_p50, consecutive_failures }`. The probe is a cheap signed `GET /v1/health` envelope-light request — no full BVRG-v1 envelope, just a master-signed nonce so Rustion can reject anonymous probes — that returns Rustion version + uptime + active session count. Three consecutive failures flip a target to `down`; one success flips it back to `up`. Status changes emit `rustion.target.health.changed` audit events. The GUI surfaces a status dot per target (Settings → Rustion bastions) and on the Connection tab, and the dispatcher (below) skips any target not in `up` status when picking an instance.
- **Bastion selection on a resource** — a `rustion` connection profile carries a `bastions` field which is **either**:
  - **A non-empty ordered list** of Rustion target ids — BastionVault tries them **in declared order**, opens the session on the first one whose `health.status = "up"` and which accepts the envelope. Failures (network error, control-plane 5xx, `down` health) advance to the next entry; an explicit `403 / 401` from a reachable Rustion does **not** fall through (a permission denial is final and surfaces to the operator). This is how an operator pins primary + DR, or "regional first, fall back to corporate."
  - **Empty / unset** — the dispatcher draws **uniformly at random** from the pool of all globally-enabled targets whose `health.status = "up"`. Random (rather than round-robin) is intentional: it spreads load without requiring shared state across BastionVault HA replicas, and the operator's individual session isn't a hot path that benefits from stickiness. The chosen target is recorded on the `session.open` event so audit replay is unambiguous.
  
  In both modes, if every candidate is unhealthy or rejects, the Connect attempt fails with `bastion_unavailable` and the operator sees the per-target error list. The GUI Connection tab shows a live preview of the dispatcher's choice ("Will try: rustion-eu-west-1 → rustion-eu-west-2") that updates as health changes.
- **Session-grant envelope** — a versioned binary format (BVRG-v1) that bundles `{target, credential_material, operator_identity, ttl_seconds, max_renewals, recording_policy, audit_correlation_id}` and travels as `sign(master_priv, encrypt(rustion_pub, cbor(payload)))`. Reuses the existing crypto crate (ChaCha20-Poly1305 + ML-KEM-768 + ML-DSA-65 stack).
- **New connection-profile kind: `rustion`** — alongside the existing `direct` profiles on each server resource, a profile may declare `kind: "rustion"` with a `bastions: <ordered list of rustion-target-ids>` field (empty/unset = pick at random from the global pool, see *Bastion selection* above) and an optional `recording_policy` override. The credential source resolution stays identical (Secret / LDAP / SSH-engine / PKI); only the *transport* changes.
- **Session ticket UX** — the existing SSH / RDP session windows take a new `transport: "rustion"` mode and connect to `rustion-host:rustion-port` with the one-shot ticket as a SASL-style credential. xterm.js + ironrdp surfaces are unchanged; only the dialler swaps.
- **Renewal API** — `POST /v1/rustion/sessions/{sid}/renew` re-signs a grant with the master cert if policy allows and the original session is still active. The GUI fires renewal at `ttl - 60s` with exponential backoff. Limited by `max_renewals` from the original grant.
- **Forced revocation** — `DELETE /v1/rustion/sessions/{sid}` issues a signed `kill` envelope; Rustion drops the session immediately. Surfaced as a "Terminate" button on the active-sessions panel.
- **Recording pointer** — Rustion returns `{recording_id, started_at, finished_at, sha256, format, location}` on session close. BastionVault stores it on the `session.close` audit event and exposes a "Open recording" link in the audit timeline that streams the file from Rustion (signed-URL style; the bytes never sit in BastionVault).
- **Session replay in-GUI** — the audit timeline's "Open recording" link launches an in-app player rather than handing the operator a raw file. For asciicast v3 (SSH) the GUI mounts an `asciinema-player` instance and streams the cast bytes from Rustion via `GET /v1/recordings/{rid}` with a per-request signed envelope. For `.rdp-rec` (RDP) the GUI ships a small WASM decoder that decompresses the bitmap-event stream into a `<canvas>`-rendered replay. Both players surface scrub bar + play/pause + per-event metadata; neither caches the raw bytes outside the WebviewWindow's memory.
- **Telemetry pull from Rustion** — BastionVault polls four read-only Rustion endpoints (per authority, so each BV instance only ever sees its own sessions and audit entries):
  - `GET /v1/sessions/active` — live sessions Rustion is currently mediating *for this authority*: `{session_id, operator_vault_user, target, opened_at, expires_at, bytes_in, bytes_out, recording_id}`. Drives a new **"Live sessions"** page (admin-gated) in the GUI that auto-refreshes every 5s. The "Terminate" button hits `DELETE /v1/rustion/sessions/{sid}` from Phase 5.
  - `GET /v1/sessions/history?since=<ts>&limit=<n>` — closed-session metadata for the audit timeline: open + close timestamps, target, operator, duration, total bytes, terminate-reason, recording link. Cursor-paged so a fresh BastionVault can backfill the history of a long-running Rustion at first sync.
  - `GET /v1/sessions/audit?since=<ts>&limit=<n>` — Rustion's own hash-chain entries scoped to this authority (`session.open`, `session.renew`, `session.terminate`, `envelope.rejected`, `authority.reload`). BastionVault verifies each entry's signature against the pinned Rustion pubkey and folds it into its **own** hash-chain log under a `rustion.audit.witness` event. The two chains become independent witnesses of the same session — losing either still lets an auditor reconstruct what happened.
  - `GET /v1/stats?bucket=hour&since=<ts>` — aggregate metrics buckets: `{authority, avg_session_secs, max_session_secs, sessions_opened, sessions_terminated_by_user, sessions_terminated_by_admin, sessions_expired, bytes_total, top_targets, top_operators}`. Surfaces in a **"Rustion analytics"** dashboard (admin-gated): a chart of sessions-per-hour, top-10 operators by session count, top-10 targets, average session length, and an envelope-rejection breakdown.
  All four endpoints use the same lightweight signed-nonce auth as `GET /v1/health` so each poll cycle is cheap. Pull cadence is configurable (`sys/config/rustion.telemetry_interval_secs`, default 60s); a manual "Sync now" button on the Live sessions page forces an immediate refresh.
- **Trust establishment — explicit Rustion-side approval of BastionVault installations** — enrolling a BastionVault as a Rustion authority is intentionally a **two-sided handshake**, not a one-way pubkey paste:
  1. Operator on the BastionVault side exports the master pubkey via `bvault rustion master export` (or the GUI button) and submits it to the Rustion side. The submission carries the BV master pubkey, BV deployment id (a stable UUID minted on first PKI init), display name, requested `allowed_targets` glob list, and requested `allowed_actions`.
  2. The submission lands in Rustion's **pending-authorities** holding pen (`/etc/rustion/authorities-pending/`, not the active `authorities/` directory). It is **inert** — Rustion refuses envelopes signed by a pending authority with `403 authority_pending_approval`.
  3. A Rustion admin reviews the request via TUI (`rustion authority approve --name <n>`), CLI, or the admin web UI, optionally tightening `allowed_targets` / `allowed_actions` / `max_session_secs`. Approval moves the YAML from the holding pen into `authorities/` and is logged in Rustion's hash chain as `authority.approved`. Rejecting writes an `authority.rejected` entry and leaves a stamped tombstone for audit.
  4. After approval, BastionVault re-attempts the next envelope — Rustion's hot-reloader has picked up the new authority record, the envelope verifies, and traffic flows.
  - **Periodic re-attestation** — every authority record carries an `attestation_renew_at` timestamp. On read, Rustion checks the BV deployment id matches the one recorded on enrolment; if it doesn't, the envelope is refused with `403 attestation_mismatch` (this catches a stolen master keypair being re-used by a different vault). BastionVault re-attests via a signed envelope listing its current deployment id once per week; Rustion bumps the timestamp on acceptance.
  - **Revocation propagation** — when an operator deletes / revokes a Rustion target on the BastionVault side, BastionVault sends a final `op = "deenrol"` envelope to Rustion. Rustion's handler moves the authority into a `tombstoned/` directory (still indexed for audit-replay) and rejects any further envelope from that pubkey with `403 authority_tombstoned`, even before the next hot-reload. Symmetrical revocation on the Rustion side (admin deletes the authority record) immediately stops accepting traffic; BastionVault detects the failure mode via the standard health-probe path and surfaces `bastion_rejected_authority` in the GUI.
  - **Net result** — a Rustion that has *not* approved a given BastionVault will silently refuse every operation from it, even if the master pubkey was somehow pasted into its config. There is no "trust on first signed envelope" path; the human-in-the-loop approval is a hard gate.
- **Audit events** — `rustion.target.enrol`, `rustion.target.rotate`, `rustion.target.health.changed`, `rustion.target.deenrol`, `rustion.bastion_group.update`, `rustion.master.issue`, `rustion.master.rotate`, `rustion.master.attest`, `rustion.authority.approval_pending` (submission queued on Rustion's side), `rustion.authority.approved`, `rustion.authority.rejected`, `rustion.authority.tombstoned`, `rustion.authority.untombstoned`, `rustion.policy.global.update`, `rustion.policy.type.update`, `rustion.policy.asset_group.update`, `rustion.policy.resource.update`, `rustion.audit.witness` (re-attested Rustion hash-chain entry mirrored into BV's chain), `session.open` (extended with `transport: "rustion" | "direct"`, `bastion_id`, `bastion_group?: string`, `bastion_selection: "pinned" | "ordered-fallback" | "random-pool" | "group"`, `bastion_candidates_tried`, `policy_chain` (the resolved tier chain that produced these values), `rustion_session_id`), `session.renew`, `session.terminate`, `session.replicated` (telemetry-derived from Rustion's history endpoint), `recording.linked`, `recording.replayed` (in-GUI playback opened; carries operator id + recording id + access window).
- **Bastion-group selection (named pools of Rustion instances)** — on top of the per-profile `bastions` list and the implicit global pool, operators may define **named bastion groups** under `sys/config/rustion/bastion-groups/<name>` (e.g. `eu-prod`, `dr-corp`, `pci-zone`). A bastion group is just an ordered list of Rustion target ids plus an optional `selection: "ordered" | "random"` flag. Resources, asset groups, and resource types can then reference a bastion group **by name** rather than copying the same target-id list onto every profile. The dispatcher resolves a group name to its current member list at session-open time, so re-pointing an entire fleet from one DR pair to another is a single edit. Group membership is admin-scoped (writes on `sys/config/rustion/bastion-groups/*`), reads are anyone-with-Connect.
- **Four-tier transport-and-bastion policy** — a new `connect` block carrying `{ transport: "direct" | "rustion" | "rustion-required", bastions: <ordered list of target ids> | <bastion-group name>, recording: "always" | "off" | "input-redacted" }` applied at **four levels**, evaluated **most-restrictive-wins for `transport`** and **nearest-tier-wins for `bastions` / `recording`**:
  1. **Global default** — a deployment-wide setting in `sys/config/rustion` (`transport_default`, `bastion_group_default`, `recording_default`, `transport_lock`). When `transport_lock = true`, the global value pins every resource and downstream overrides are ignored. This is how an admin says *"all Connect, everywhere, must go through one of these bastions."*
  2. **Per-resource-type** — `connect.transport` / `connect.bastions` / `connect.recording` on `ResourceTypeDef`, overrides the global default for resources of that type *only if its `transport_lock` is false*. Per-type lock available so a vault admin can pin all `server` resources to Rustion while leaving other resource types free.
  3. **Per-asset-group** — `connect.transport` / `connect.bastions` / `connect.recording` on an [asset group](asset-groups.md) (a named collection of resources). When a resource belongs to multiple groups, the **most-restrictive** transport applies and the **first-by-priority** group supplies the bastion list (priority is an admin-set integer on the group; ties break by alphabetical group name). Per-group lock available, so e.g. the `pci-zone` asset-group can force `rustion-required` + a specific bastion pool on every resource in it regardless of who owns the resource. This tier is what lets operators say *"every resource tagged `pci` goes through the `pci-zone` bastion group, period."*
  4. **Per-resource** — `connect.transport` / `connect.bastions` / `connect.recording` on the individual resource record, overrides upstream tiers *only when no upstream tier is locked*. Owner-editable.
  
  **Resolution order:**
  - **`transport`** uses `min(global, type, asset-group(s), resource)` under the ordering `direct < rustion < rustion-required`. A resource owner who sets `direct` on their resource still goes through Rustion if any upstream tier pins `rustion`.
  - **`bastions`** uses the nearest-defined-tier wins: resource value if set, otherwise asset-group (by priority), otherwise resource-type, otherwise global. A locked upstream tier's `bastions` cannot be overridden by a downstream tier even if the downstream `transport` is permissive.
  - **`recording`** uses the strictest of `always > input-redacted > off` (an upstream `always` wins over a downstream `off`).
  
  Operators see the full resolution chain in the Connection tab ("transport `rustion-required` ← asset-group `pci-zone` (locked) / bastions `dr-corp` ← global / recording `always` ← resource-type `database` (locked)") so the source of every effective value is unambiguous.
- **Admin / root-only configuration** — writing the global `sys/config/rustion` policy, any `transport_lock` flag, and the `bastion-groups/*` definitions requires the built-in **`root`** policy or a policy that grants `update` on `sys/config/rustion/*`. Per-resource-type policy lives on `ResourceTypeDef` and requires the **`admin`** capability on `sys/config/resource-types/*` (same gate as the existing per-type Connect-enabled toggle from Resource Connect Phase 7). Per-asset-group policy requires the **`admin`** capability on `sys/asset-groups/*` plus ownership of the group (or membership in an admin policy). Per-resource policy is editable by the resource owner *only when the upstream tiers permit it* — a locked global / type / asset-group makes the field read-only in the GUI and rejected with `403 transport_locked` from the API, with a `locked_at_tier` field in the error body so the GUI can point the operator at the responsible admin. Every change emits a dedicated audit event (`rustion.policy.global.update`, `rustion.policy.type.update`, `rustion.policy.asset_group.update`, `rustion.policy.resource.update`, `rustion.bastion_group.update`) carrying actor, before/after values, and the lock state.
- **GUI: Settings → Rustion bastions** — CRUD for Rustion targets (the registry of individual instances), one-shot enrolment wizard (paste Rustion's pubkey, export master pubkey to clipboard / file), liveness ping, connection-test button. **Settings → Rustion → Bastion groups** is a separate panel: admins create / rename / reorder named groups and assign Rustion targets to them with an optional priority. **Settings → Rustion → Global policy** is a third panel, visible only to root, exposing `transport_default`, `bastion_group_default`, `recording_default`, and `transport_lock`. Resource-type policy lives in the existing Settings → Resource Types editor (admin-only). Asset-group policy lives on the Asset Groups page, on the group detail. Per-resource policy is on the resource's Connection tab, disabled with an explanatory tooltip naming the locking tier when an upstream tier has locked it.
- **CLI parity** — `bastionvault rustion target add | list | rotate-pubkey | enrol-master | test`.

### In scope (Rustion side — new control-plane surface)

- **Trusted-authority store** — a new `authorities/<name>.yaml` directory parallel to `users/`. Each entry: `{name, type: "external-vault", pubkey: <hybrid pub>, enrolled_at, fingerprint, allowed_targets: [<glob>], allowed_actions: [open|renew|terminate], max_session_secs}`. Hot-reloaded like users.
- **Control-plane endpoint** — a TLS-only HTTP/2 listener (`rustion serve --control-plane <bind>`) accepting four operations:
  - `POST /v1/sessions` — body is a BVRG-v1 envelope. Rustion verifies signature, decrypts, materialises a session, returns `{session_id, host, port, ticket, expires_at}`.
  - `POST /v1/sessions/{sid}/renew` — extends TTL on a re-signed envelope.
  - `DELETE /v1/sessions/{sid}` — terminates on a signed kill envelope.
  - `GET /v1/recordings/{rid}` — returns a short-lived signed URL the operator can stream from. Optional, can be off in air-gapped deployments.
  - `GET /v1/health` — cheap health probe: accepts a master-signed nonce (lightweight, not a full BVRG-v1 envelope), returns `{version, uptime_secs, active_sessions, build_sha}`. Rate-limited per source IP and per authority so a misconfigured pinger can't flood it.
- **Session ticket protocol** — when the operator's client connects to the SSH or RDP listener, the first thing it presents is `ticket@<session_id>`. Rustion looks up the materialised session, binds the socket to it, and proxies to the target with the decrypted credential. Tickets are single-use, IP-bound, and expire on first connect or after 30s, whichever comes first.
- **Recording handoff** — on session close, Rustion writes a JSON sidecar with `{recording_id, sha256, format, started_at, finished_at, target, authority}` to a directory the BastionVault control plane can poll, and emits an outbound `recording.ready` webhook (signed) to a configurable URL.
- **External-authority audit** — every action driven by a verified BVRG-v1 envelope is logged in Rustion's hash chain with the authority name + envelope fingerprint, so Rustion's own audit log is a tamper-proof witness independent of BastionVault's.

### Out of scope (explicit)

- **Rustion as a federated identity provider for BastionVault.** Operators still log into BastionVault directly. The integration is one-way: BastionVault → Rustion as a *resource*, not Rustion → BastionVault as an IdP. Federation is a separate, much larger feature.
- **SMB through Rustion.** Rustion ships an SMB proxy; we don't model SMB resources in BastionVault yet. Once a `share` resource type lands, plugging it into the same envelope flow is mechanical, but it's not part of v1.
- **Pull-based session enumeration.** BastionVault does not poll Rustion for active sessions to render in its own UI; it only knows about sessions it created. A future "live sessions across all bastions" view can layer on top.
- **Migrating existing direct Connect to Rustion automatically.** Operators must opt in per resource-type or per resource. We do not silently re-route.
- **Re-implementing Rustion's recording pipeline inside BastionVault.** That was rejected in the Resource Connect spec and stays rejected. The integration's whole point is to *not* do that.
- **Multi-bastion failover for a single session.** A session is bound to one Rustion instance. If that Rustion goes down mid-session, the operator reconnects via a sibling bastion as a *new* session. HA / mesh routing of in-flight sessions is its own product.
- **End-to-end encryption between operator and target through Rustion.** Rustion is a *terminating* proxy by design (recording requires plaintext at the bastion). That tradeoff is inherited from Rustion; this feature does not try to bypass it.
- **Replacing the existing direct Connect path.** `direct` and `rustion` profiles coexist on the same resource. Operators with an existing direct workflow keep it.

## Design

### Trust model

```
                      enrolment (one-shot, manual)
   ┌───────────────────────────────────────────────────────────┐
   │  master_pub (Ed25519 + ML-DSA-65 hybrid)                  ▼
┌────────────────┐                                       ┌─────────────────────┐
│  BastionVault  │                                       │       Rustion       │
│                │   1. POST /v1/sessions  (BVRG-v1)     │                     │
│  master_priv   │ ─────────────────────────────────────▶│ verify(master_pub)  │
│  rustion_pub   │   sig=master_priv(envelope)           │ decrypt(rustion_priv)│
│                │   env=encrypt(rustion_pub, payload)   │ materialise session │
│                │ ◀───────────────────────────────────  │                     │
│                │   {sid, host, port, ticket, exp}      │                     │
└────────────────┘                                       └─────────────────────┘
        │                                                          ▲
        │                                                          │
        ▼                                                          │ 4. ticket@sid
┌────────────────┐                                                 │
│  Operator GUI  │ ──────── 4. SSH/RDP to host:port ────────────── ┘
│ (Tauri window) │
└────────────────┘
```

The trust anchor is the **master cert**, not a TLS handshake or a shared secret. That gives us:

- **Stateless verification on Rustion** — Rustion does not need to talk to BastionVault to authorise a session; it just verifies a signature against a pubkey it already has.
- **Air-gap friendly** — once enrolled, the control plane works over any path that can carry a single HTTP request, including a one-way diode.
- **Cheap rotation** — rotating the master cert is one envelope (`rustion.master.rotate`) co-signed by the old key, accepted by Rustion if the new pubkey is presented before the old one expires.

### Envelope format — BVRG-v1

```text
BVRG-v1 := magic("BVRG\x01") || sig_len:u16 || sig || ct_len:u32 || ct

sig := sign(master_priv, sha256(magic || ct_len || ct))   // hybrid Ed25519+ML-DSA-65
ct  := ML-KEM-768-encap(rustion_pub) || ChaCha20-Poly1305(payload, dek)

payload (CBOR) := {
  v: 1,
  op: "open" | "renew" | "kill",
  nonce: bytes(16),                  // anti-replay
  issued_at: timestamp,
  not_after: timestamp,              // signature validity, distinct from session TTL
  target: { host, port, protocol, hostkey_pin? },
  credential: {
    kind: "ssh-key" | "ssh-password" | "rdp-password" | "rdp-cert" | ...,
    material: bytes,                  // protocol-specific, e.g. PEM key
    username: string,
    extra: { ... }
  },
  session: {
    ttl_secs: u32,
    max_renewals: u8,
    recording: "always" | "off" | "input-redacted"
  },
  operator: {
    vault_user_id, vault_user_name, vault_session_id, src_ip
  },
  correlation_id: uuid                // links to BastionVault audit chain
}
```

Reuses the existing crypto stack (`bastion-vault-crypto`); no new primitives. Replay protection is the `nonce` plus a sliding window on Rustion (default 5 min, persisted in the authority record).

### Connection-profile kind: `rustion`

Extends the connection profiles introduced in Resource Connect Phase 2. A profile is now:

```ts
type ConnectionProfile =
  | { id: string; name: string; kind: "direct"; credential_source: ...; }
  | { id: string; name: string; kind: "rustion";
      /** Bastion selection. Exactly one of `bastions` (an ordered list of
       *  target ids) or `bastion_group` (the name of a group defined under
       *  sys/config/rustion/bastion-groups). Both empty / unset = inherit
       *  from upstream tier (asset-group → type → global → random pool). */
      bastions?: string[];
      bastion_group?: string;
      credential_source: ...;
      recording?: "always" | "off" | "input-redacted"; };
```

The credential-source resolver is unchanged (Secret / LDAP / SSH-engine / PKI). The only difference is what happens *after* resolution: a `direct` profile hands the credential to the local SSH/RDP dialler, a `rustion` profile hands the credential to the envelope builder. The dispatcher resolves bastion selection in this precedence: profile `bastions` (literal list) → profile `bastion_group` (name lookup) → asset-group `bastions` / `bastion_group` (highest-priority group the resource belongs to) → resource-type `bastions` / `bastion_group` → global `bastion_group_default` → random pool of healthy enabled targets.

### Tauri command surface (additions)

- `rustion_target_list() -> Vec<RustionTarget>` — every enrolled instance.
- `rustion_target_upsert(target: RustionTargetInput) -> RustionTarget`
- `rustion_target_test(id: String) -> { latency_ms, version, fingerprint }`
- `rustion_target_health(id: Option<String>) -> Vec<{ id, status, last_ok_at, latency_ms_p50, consecutive_failures }>` (omit id = all targets)
- `rustion_bastion_group_list() -> Vec<BastionGroup>` — named pools of Rustion targets (`{name, members: [{target_id, priority}], selection: "ordered" | "random", description}`).
- `rustion_bastion_group_upsert(group: BastionGroupInput) -> BastionGroup`
- `rustion_bastion_group_delete(name: String) -> ()` — refuses when the group is referenced by any locked tier.
- `rustion_dispatcher_preview(resource_id, profile_id) -> { mode: "pinned" | "ordered-fallback" | "random-pool" | "group", group_name?: string, source_tier: "profile" | "asset-group" | "resource-type" | "global", candidates: [{ id, name, status }] }`
- `rustion_master_pubkey_export() -> { pem, fingerprint, algs }`
- `rustion_session_open(resource_id, profile_id) -> { sid, host, port, ticket, expires_at, bastion_id }`
- `rustion_session_renew(sid: String) -> { new_expires_at }`
- `rustion_session_terminate(sid: String) -> ()`
- `rustion_recording_url(sid: String) -> { url, expires_at }`
- `rustion_recording_replay(rid: String) -> { url, format, sha256, expires_at }` — signed-URL the in-GUI player streams from.
- `rustion_policy_effective(resource_id: String) -> { transport, bastions, recording, chain: [{ tier, value, locked }] }` — full resolution chain so the GUI can render the source-of-truth tooltip.
- `rustion_sessions_active() -> Vec<LiveSession>` — drives the "Live sessions" admin page (5s auto-refresh).
- `rustion_sessions_history(since: Option<String>, limit: u32) -> Page<ClosedSession>` — backfill the audit timeline; cursor-paged.
- `rustion_sessions_audit(since: Option<String>, limit: u32) -> Page<RustionAuditEntry>` — hash-chain entries from Rustion, signature-verified server-side before being handed to the GUI.
- `rustion_stats(bucket: "hour" | "day", since: String) -> RustionStats` — analytics dashboard data.
- `rustion_authority_attest() -> { attested_at, expires_at }` — manual trigger for the periodic re-attestation (also runs on a weekly background timer).
- `rustion_target_deenrol(id: String) -> ()` — send the `deenrol` envelope and delete the local registry entry in one step.

The existing `ssh_session_open` / `rdp_session_open` commands take a new optional `transport: { kind: "rustion", sid: String, host: String, port: u16, ticket: String }` argument — when present, they dial Rustion instead of the resource's `host:port`.

### HTTP API (additions)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/v1/rustion/targets` | List enrolled Rustion bastions |
| `POST` | `/v1/rustion/targets` | Register a new Rustion bastion (paste pubkey) |
| `PUT` | `/v1/rustion/targets/{id}` | Update endpoint / pubkey |
| `DELETE` | `/v1/rustion/targets/{id}` | Remove (refuses if active sessions exist) |
| `POST` | `/v1/rustion/targets/{id}/test` | Liveness + version probe (synchronous, on-demand) |
| `GET` | `/v1/rustion/targets/health` | Cached health for every enrolled target (background-poller view) |
| `GET` | `/v1/rustion/bastion-groups` | List named pools of Rustion targets |
| `POST` | `/v1/rustion/bastion-groups` | Create / update a named pool (members, priorities, selection mode) |
| `DELETE` | `/v1/rustion/bastion-groups/{name}` | Remove (refuses if referenced by a locked tier) |
| `GET` | `/v1/rustion/master/pubkey` | Export master pub (one-shot enrol step) |
| `POST` | `/v1/rustion/master/rotate` | Rotate master cert (co-signed envelope to all enrolled bastions) |
| `POST` | `/v1/rustion/sessions` | Open a new session (consumed by GUI / CLI) |
| `POST` | `/v1/rustion/sessions/{sid}/renew` | Renew |
| `DELETE` | `/v1/rustion/sessions/{sid}` | Force-terminate |
| `GET` | `/v1/rustion/sessions` | List active sessions (BastionVault's own view) |
| `GET` | `/v1/rustion/sessions/{sid}/recording` | Resolve a streaming URL for the recording |
| `GET` | `/v1/rustion/sessions/active` | Live sessions across every enrolled bastion (proxies `GET /v1/sessions/active` per target, merged + de-duped) |
| `GET` | `/v1/rustion/sessions/history?since=<ts>` | Closed-session metadata across every enrolled bastion (audit-timeline backfill) |
| `GET` | `/v1/rustion/sessions/audit?since=<ts>` | Rustion's hash-chain entries scoped to this BV authority, signature-verified and re-witnessed into BV's own chain |
| `GET` | `/v1/rustion/stats?bucket=hour` | Aggregate session metrics (sessions/hour, top operators, top targets, durations) |
| `POST` | `/v1/rustion/recordings/{rid}/replay` | Mint a one-shot signed URL the GUI player streams from; bytes never traverse BastionVault |
| `POST` | `/v1/rustion/master/attest` | Periodic re-attestation: BV announces its current deployment id, refreshes Rustion's `attestation_renew_at` |
| `DELETE` | `/v1/rustion/targets/{id}/enrolment` | Send a `deenrol` envelope so Rustion tombstones this BV authority (called automatically when the target is deleted; surfaced standalone for `bvault rustion target deenrol`) |
| `GET` | `/v1/rustion/policy` | Read effective global + per-type defaults (any authenticated operator) |
| `PUT` | `/v1/rustion/policy` | Update global `transport_default` / `bastion_group_default` / `recording_default` / `transport_lock` (**root only**) |
| `GET` | `/v1/rustion/policy/type/{type_id}` | Read per-resource-type policy |
| `PUT` | `/v1/rustion/policy/type/{type_id}` | Update per-resource-type policy (**admin only**) |
| `GET` | `/v1/rustion/policy/asset-group/{group_id}` | Read per-asset-group policy |
| `PUT` | `/v1/rustion/policy/asset-group/{group_id}` | Update per-asset-group policy (**admin or group owner**) |
| `GET` | `/v1/rustion/policy/effective?resource={id}` | Resolve the effective transport / bastions / recording for a specific resource, returning the full resolution chain so callers can render the source-of-truth chip |

All endpoints are policy-gated on `rustion/*` paths in the existing ACL grammar.

### Multi-instance failover (BastionVault-side HA)

Availability on the `rustion-required` path is provided here, in BastionVault, rather than by building active/passive HA inside Rustion. The pieces (all shipped — see Phases 1, 3.2, 7.1, 9.3):

- **Many enrolled instances.** The `rustion/` registry holds N instances, each with its own pinned hybrid identity; removing or rotating one is local.
- **Health-driven candidate selection.** A background pinger marks each instance `up`/`degraded`/`down`/`unknown`; the dispatcher only ever considers `up` targets.
- **Three selection shapes**, all health-filtered:
  - **`ordered-fallback`** — a profile/tier-pinned ordered list; tried top-to-bottom (primary → DR → …).
  - **`group`** — a named bastion group resolved to its members, walked in declared order (`selection: ordered`) or shuffled (`selection: random`).
  - **`random-pool`** — no list pinned; a uniform random draw from all healthy enabled targets (no shared state across BV HA replicas).
- **Walk-and-advance.** On a transport error or 5xx the dispatcher advances to the next candidate; a 4xx (a real permission denial) halts so the operator isn't bounced across every bastion. If every candidate is unhealthy or rejects, Connect fails with `bastion_unavailable`.
- **Single-session caveat.** A *session* is still bound to one instance; if that instance dies mid-session the operator reconnects as a *new* session on a sibling. The *service* has no single point of failure, but in-flight session migration is explicitly out of scope.

Operators preview the live choice for a resource via `rustion_dispatcher_preview` ("Will try: rustion-eu-west-1 → rustion-eu-west-2"). Regulated deployments should enrol ≥2 instances in distinct failure domains and pin them with an ordered group.

### Worked example — a real multi-instance deployment

A medium-size deployment with three regions, a PCI zone, and a DR pair might look like this. The example is illustrative — it shows how the four policy tiers compose without anybody having to hand-edit every resource.

```
Enrolled Rustion instances
──────────────────────────
  rustion-eu-west-1            (prod EU west, primary)
  rustion-eu-west-2            (prod EU west, DR)
  rustion-eu-central-1         (prod EU central)
  rustion-us-east-1            (prod US east)
  rustion-pci-1                (PCI zone, dedicated VRF)
  rustion-pci-2                (PCI zone, DR)
  rustion-corp                 (corporate fallback)

Bastion groups (defined under sys/config/rustion/bastion-groups/)
────────────────────────────────────────────────────────────────
  eu-prod          : [rustion-eu-west-1, rustion-eu-west-2, rustion-eu-central-1]   selection: ordered
  us-prod          : [rustion-us-east-1]                                            selection: ordered
  pci-zone         : [rustion-pci-1, rustion-pci-2]                                 selection: ordered
  global-fallback  : [rustion-corp]                                                 selection: ordered

Global policy (sys/config/rustion)
──────────────────────────────────
  transport_default   = rustion             # default is bastion, can be overridden
  bastion_group_default = global-fallback   # last-resort pool
  recording_default   = always
  transport_lock      = false               # downstream can still pick direct

Per-resource-type policy (ResourceTypeDef "database")
─────────────────────────────────────────────────────
  connect.transport      = rustion-required  # databases ALWAYS through a bastion
  connect.bastion_group  = eu-prod           # default to EU pool
  connect.recording      = always
  transport_lock         = true              # downstream cannot weaken

Per-asset-group policy ("pci-prod-cardholders")
───────────────────────────────────────────────
  priority               = 100                # higher than other groups
  connect.transport      = rustion-required
  connect.bastion_group  = pci-zone
  connect.recording      = always
  transport_lock         = true

Per-resource policy (resource "warehouse-db.eu" — type database, member of pci-prod-cardholders)
────────────────────────────────────────────────────────────────────────────────────────────────
  connect.transport      = direct             # ❌ ignored, pci-prod-cardholders locked it
  connect.bastions       = [rustion-corp]     # ❌ ignored, pci-prod-cardholders locked the group
```

Resolved effective policy for `warehouse-db.eu`:

```
transport  = rustion-required   ← asset-group "pci-prod-cardholders" (locked)
bastions   = group "pci-zone"   ← asset-group "pci-prod-cardholders" (locked)
recording  = always             ← asset-group "pci-prod-cardholders" (locked)
```

The Connection tab on `warehouse-db.eu` displays:

```
Bastion required (locked by asset-group "pci-prod-cardholders")
Will try: rustion-pci-1 → rustion-pci-2
Recording: always (locked)
```

If `rustion-pci-1` is `down`, the dispatcher tries `rustion-pci-2`. If both are `down`, Connect fails with `bastion_unavailable` — the operator is **not** silently dropped onto `rustion-corp`, because the locked `pci-zone` group constrains the candidate set. That hard-fail is the point of the lock.

### Enrolling a Rustion bastion — operator runbook

End-to-end procedure for taking a freshly provisioned Rustion host and
landing it in BastionVault's registry. The handshake is **two-sided**:
BastionVault has to pin Rustion's hybrid identity, and Rustion has to
approve BastionVault's master pubkey before envelopes are honoured.
Skip either half and the dispatcher will surface `unknown_authority`
on the first session attempt.

#### 0. Prerequisites

- Rustion ≥ 0.10.0 (ships the `control-plane identity export` CLI).
  Older builds: bring the host up to date, or copy `identity.pub` off
  disk manually (see step 1 footnote).
- Rustion's control-plane listener is configured and reachable from
  BastionVault — by default `127.0.0.1:8443`. Production deployments
  set `control_plane.listen = "0.0.0.0:9443"` (or similar) plus
  `tls_cert_path` / `tls_key_path` in `rustion.toml`. The endpoint
  pasted into BV is always `host:port` of this listener.
- Rustion has been started at least once so the control-plane bootstrap
  routine has materialised `<identity_dir>/identity.{pub,key}`. On a
  cold host you'll see `control-plane: identity missing — generating
  fresh ML-KEM-768 keypair` in the log on first boot.

#### 1. Export Rustion's hybrid identity (on the Rustion host)

```bash
# ML-KEM-768 encapsulation key — used by BV to seal session-grant
# envelopes to this Rustion. Base64 standard-alphabet, newline-
# terminated.
rustion control-plane identity export \
    --config /etc/rustion/rustion.toml > kem.pub.b64

# (Optional) raw bytes, e.g. to pipe into a separate signing step:
rustion control-plane identity export \
    --config /etc/rustion/rustion.toml --raw > identity.pub.bin
```

The `--kem` flag is accepted for forward compatibility but is currently
a no-op — the command always reads `<identity_dir>/identity.pub`
(ML-KEM-768, 1184 bytes raw / 1580 chars base64). The file lives under
`control_plane.identity_dir`, default `/opt/rustion/control-plane/` in
release builds and `~/.rustion/control-plane/` in debug builds. The
matching private half stays in `identity.key` with `0600` perms and is
never emitted by the CLI.

The Ed25519 + ML-DSA-65 webhook signing pair (used by Rustion to sign
outbound recording webhooks; `WebhookSigningKey` in
`crates/rustion-control-plane/src/webhook.rs`) is persisted on first
boot to `<identity_dir>/webhook.key` (64 bytes: 32B Ed25519 seed +
32B ML-DSA-65 seed, `0600`) and exported via a dedicated CLI added in
Rustion 0.10.1:

```bash
# Default JSON shape — ready to feed into a config-management
# pipeline or jq:
rustion control-plane webhook-key export \
    --config /etc/rustion/rustion.toml
# {
#   "ed25519_spki_b64": "MCowBQYDK2VwAyEA...",
#   "mldsa65_pub_b64": "MIIH...",
#   "fingerprint_sha256": "ab12cd34..."
# }

# Shell-source-able env form, handy for `bvault rustion target add`:
rustion control-plane webhook-key export --format env > webhook.env
source webhook.env
# RUSTION_WEBHOOK_ED25519=...
# RUSTION_WEBHOOK_MLDSA65=...
```

`ed25519_spki_b64` is the **SPKI-wrapped** form expected by BV's
`public_key.ed25519 (base64 SPKI)` field; `mldsa65_pub_b64` is the
1952-byte raw ML-DSA-65 public key. The `fingerprint_sha256` is
`sha256(ed25519_raw || mldsa65_raw)` hex — print it on both sides of
the enrolment to cross-check at the Rustion approval step. Persistence
means BV's pin survives Rustion restarts; rotating the webhook
keypair is currently a manual `rm webhook.key && systemctl restart
rustion` plus a re-enrolment on BV.

#### 1b. (Optional) capture the control-plane TLS cert for pinning

BastionVault verifies the Rustion control-plane TLS cert against the
standard webpki-roots bundle by default. If your Rustion is serving a
self-signed cert (lab, pre-prod, or any deployment where minting a
cert from the internal CA isn't on the critical path), enable
per-target pinning by also exporting the leaf cert:

```bash
sudo cat /srv/application-config/rustion/tls/server.crt > server.crt
```

(or wherever `control_plane.tls_cert_path` points to in
`rustion.toml`). You'll paste the PEM body into the BV enrol form's
"Advanced — pin TLS leaf certificate" section in step 2. When the
field is set, BV trusts only that leaf as a root and skips hostname
matching — pinning the exact cert already binds trust to a specific
server, so the hostname check becomes redundant. This is the
preferred way to deal with self-signed certs that lack a
`SubjectAltName` extension; the alternative (adding the cert to the
host's system CA bundle) is silently ignored by BV's `reqwest`
client, which uses bundled webpki-roots rather than the host bundle.

Leave the field empty if your Rustion serves a cert chained to a CA
already in webpki-roots — that's the standard production posture and
needs no extra config.

#### 2. Register the Rustion target on BastionVault

GUI path — **Settings → Rustion Bastions → Enrol bastion**. Paste:

| Field | Value | Source |
|---|---|---|
| Name | Operator-friendly label, unique per deployment, case-insensitive | Free-form |
| Endpoint | `host:port` of Rustion's control-plane listener | `control_plane.listen` |
| `public_key.ed25519` (base64 SPKI) | Webhook signing — Ed25519 half | `ed25519_spki_b64` from `rustion control-plane webhook-key export` |
| `public_key.mldsa65` (base64 raw) | Webhook signing — ML-DSA-65 half | `mldsa65_pub_b64` from `rustion control-plane webhook-key export` |
| `kem_public_key` (base64 raw ML-KEM-768) | Session-envelope sealing | `rustion control-plane identity export` (step 1) |
| Description / Tags / Enabled | Free-form | — |

CLI parity:

```bash
bvault rustion target add \
    --name eu-prod-1 \
    --endpoint rustion-eu-1.internal:9443 \
    --ed25519 "$(cat ed25519.spki.b64)" \
    --mldsa65 "$(cat mldsa65.pub.b64)" \
    --kem-pubkey "$(cat kem.pub.b64)" \
    --description "EU west primary" \
    --tags "region=eu-west-1,zone=prod"
```

Both paths refuse a classical-only submission (`ed25519` set,
`mldsa65` empty) as a downgrade attack. IDs are derived deterministi-
cally from the lowercased name, so a CLI re-submission lands on the
same record as the wizard — useful for declarative provisioning.

After save, BV transitions the target through `Unknown → Up` once the
30s health pinger ([`probe.rs`](../src/modules/rustion/probe.rs)) sees
a `200 OK` from `GET /v1/health`. The wizard's **Test Connection**
button (`POST /v1/rustion/targets/{id}/probe`) forces a single
on-demand probe so operators don't have to wait for the next sweep.

#### 3. Export BastionVault's master pubkey (on BastionVault)

```bash
bvault rustion master export --output bv-master.b64
# or, GUI: Settings → Rustion Bastions → "Export master pubkey"
```

This emits the hybrid Ed25519 + ML-DSA-65 master signing pubkey along
with BV's `deployment_id` — both required at the Rustion approval
step. The same file can be re-used across every Rustion target in the
deployment; rotating the master cert invalidates it.

#### 4. Submit to Rustion's pending queue

BastionVault automatically posts the master pubkey to
`POST /v1/authority/submit` on every newly enrolled target. The
submission lands in `<authorities_dir>/authorities-pending/<n>.yaml`
on the Rustion side, inert (envelopes return `403
authority_pending`) until an admin approves it. To trigger the
submission manually — e.g. after re-establishing connectivity to a
previously-unreachable target — use
`POST /v1/rustion/targets/{id}/reattest` or the wizard's **Re-submit
enrolment** button.

#### 5. Approve on Rustion

```bash
# On the Rustion host, as an operator:
rustion authority list-pending
# NAME                        SUBMITTED-AT          DEPLOYMENT-ID
# bv-eu-prod                  2026-05-22T14:02:11Z  d-7f3a…

rustion authority approve --name bv-eu-prod \
    --max-session-secs 28800 \
    --replay-window-secs 300
# moves authorities-pending/bv-eu-prod.yaml → authorities/bv-eu-prod.yaml
# pins deployment_id; writes authority.approved to the hash chain
```

`approve` is the moment Rustion starts accepting envelopes signed by
the submitted master pubkey. `max-session-secs` is the per-authority
upper bound on requested TTLs (default 8h); `replay-window-secs` is the
clock-skew tolerance for envelope nonce freshness (default 5 min).

Use `rustion authority reject --name <n> --reason "<why>"` to send
the submission to `tombstoned/` instead — the operator on the BV side
will see `authority_tombstoned` on the next probe and must investigate
before re-submitting.

#### 6. Verify end-to-end

```bash
# On BastionVault — open + close a no-op session against the target:
bvault rustion target test --id <target-id>
# expects: probe_ok=true, envelope_accepted=true, session_open=true
```

The GUI surfaces the same call as **Test Session** on the target row.
A green check on both *Health* and *Trust* columns means the target is
ready for production traffic. From this point onwards the dispatcher
will route sessions to it under whatever policy chain selects it.

#### 7. Day-2 operations

- **Re-attestation** runs weekly from BV (`POST /v1/rustion/master/attest`);
  if it fails three times, the target flips to `attestation_stale` and
  is excluded from the dispatcher until the operator re-runs step 4.
- **Master rotation** issues a fresh master cert and resubmits to every
  enrolled Rustion. Rustion treats it as a key rotation (same
  `deployment_id`, new `current_pubkey`) and the admin re-approves
  with `rustion authority approve` — the workflow is identical to a
  first enrolment, except the pending YAML is annotated as a rotation
  in the diff column.
- **De-enrolment** — deleting the target on BV sends a final signed
  `deenrol` envelope; Rustion moves the authority into `tombstoned/`
  and refuses further envelopes from that pubkey forever. The
  tombstone survives admin restarts and cannot be cleared without an
  explicit `rustion authority untombstone <n>`.
- **Symmetric revocation** — if the Rustion admin runs
  `rustion authority deenrol --name bv-eu-prod` first, BV's next probe
  sees the `authority_tombstoned` response and surfaces
  `bastion_rejected_authority` on the target row.

### Module / file layout (BastionVault)

```
src/modules/rustion/
  mod.rs                      // mount point, route registration
  config.rs                   // RustionTarget, RustionMaster, deployment-id slot
  envelope.rs                 // BVRG-v1 build / verify
  client.rs                   // HTTP/2 client to Rustion control plane
  health.rs                   // background pinger + status cache + state-change events
  telemetry.rs                // background sessions / audit / stats puller + cursor store
  bastion_group.rs            // named pools of targets (sys/config/rustion/bastion-groups/*)
  dispatcher.rs               // bastion selection: literal list, group lookup, random pool
  policy.rs                   // four-tier resolver (global / type / asset-group / resource)
  master.rs                   // master cert lifecycle (issue, rotate, export, re-attest)
  enrolment.rs                // submit / pending / approval / tombstone state machine
  session.rs                  // session open / renew / terminate state machine
  recording.rs                // recording-pointer storage + signed-URL fetch + replay shim
  audit.rs                    // event taxonomy (incl. rustion.audit.witness)
  http.rs                     // axum routes
  cli.rs                      // `bastionvault rustion ...`
gui/src/lib/rustion.ts        // typed Tauri command wrappers
gui/src/routes/SettingsPage.tsx        // + Rustion Bastions + Bastion Groups + Global policy
gui/src/routes/AssetGroupsPage.tsx     // + per-group transport / bastion / recording policy
gui/src/routes/ResourcesPage.tsx       // + transport selector + effective-policy chip on the Connection tab
gui/src/routes/AuditPage.tsx           // + recording link rendering + session.replicated rows
gui/src/routes/RustionLiveSessionsPage.tsx  // admin-only live sessions across the fleet
gui/src/routes/RustionAnalyticsPage.tsx     // admin-only sessions-per-hour / top-N dashboard
gui/src/routes/SessionReplayWindow.tsx      // asciicast / .rdp-rec player (isolated WebviewWindow)
```

### Module / file layout (Rustion)

```
crates/rustion-control-plane/  // new crate
  src/
    lib.rs
    authority.rs              // YAML authority store, hot-reload
    envelope.rs                // BVRG-v1 verify + decrypt (mirror of BV side)
    routes.rs                  // axum service: /v1/sessions, /v1/recordings
    session.rs                 // ticket vending + lifecycle
    webhook.rs                 // outbound recording.ready signing
crates/rustion-server/         // wires the new crate into the main binary
```

### Recording flow

1. Session opens → Rustion records natively (asciicast / `.rdp-rec`) under `/var/lib/rustion/recordings/<authority>/<yyyy>/<mm>/<dd>/<sid>.{cast,rdp-rec}`.
2. On close, Rustion writes the sidecar JSON and POSTs a signed `recording.ready` webhook to the URL in the authority config.
3. BastionVault's webhook handler verifies the signature against the same trust anchor (Rustion's pinned pubkey) and writes a `recording.linked` audit event, attaching `{sid, recording_id, sha256, format, location}` to the existing `session.close` event.
4. When the operator clicks "Open recording" in the audit UI, BastionVault calls `GET /v1/recordings/{rid}` on Rustion with a freshly-signed envelope; Rustion returns a 60-second signed URL that the GUI streams from. The bytes never traverse BastionVault.

### Telemetry pull

A background task (`src/modules/rustion/telemetry.rs`) loops every `telemetry_interval_secs` (default 60s, configurable under `sys/config/rustion`) and, for every target with `health.status = "up"`:

1. Hits `GET /v1/sessions/active` with the same lightweight signed-nonce auth the health pinger uses. Result merged into an in-memory cache the **Live sessions** page renders. De-dupes on `session_id` (which is unique per Rustion instance, prefixed implicitly by the bastion id) so a single operator session never shows twice.
2. Tracks per-target `since_history_at` and `since_audit_at` cursors. On every cycle, calls `GET /v1/sessions/history?since=<since_history_at>` and `GET /v1/sessions/audit?since=<since_audit_at>` to page through everything new; updates the cursor on success, retries on next cycle on failure. New history rows are written to BV's audit timeline as `session.replicated` events linking back to the Rustion `session_id` + recording id; new audit entries are written as `rustion.audit.witness` after verifying their signature against the pinned Rustion pubkey.
3. Hits `GET /v1/stats?bucket=hour&since=<since_stats_at>` and folds the bucket into a sparse persisted aggregate at `rustion/stats/<authority>/<bucket>/<ts>`. The analytics dashboard reads from this aggregate, not directly from Rustion, so a temporarily-unreachable bastion doesn't blank out the chart.

The cache + cursors persist under `rustion/telemetry/<target_id>/` so a restart of BastionVault doesn't refetch the entire history. A new field `telemetry_paused_at` lets an operator pause polling per target (the GUI button surfaces in the target row when a bastion is in `down` for >5min, since continued polling against a known-dead endpoint just bloats the cache).

### Session replay

```
┌─────────────────────────────────────────────────────────┐
│  Audit timeline → row clicked                           │
│                                                          │
│  GUI calls rustion_recording_replay(rid)                │
│   → POST /v1/rustion/recordings/{rid}/replay            │
│   → BV constructs a fresh signed envelope (op="replay") │
│   → POSTs it at the Rustion instance that owns the rec  │
│   → Rustion returns {url, sha256, expires_at, format}   │
│                                                          │
│  GUI opens a SessionReplayWindow (separate Tauri        │
│  WebviewWindow, isolated context)                       │
│   - asciicast: asciinema-player streams from `url`      │
│   - .rdp-rec : in-tree WASM decoder paints to <canvas>  │
│  Player tears down on close; bytes never persist locally│
└─────────────────────────────────────────────────────────┘
```

Bytes never traverse BastionVault. The signed URL is 60-second TTL, IP-bound to the requesting operator's source IP, and refused after first stream-end so a leaked URL is useless. SHA-256 is returned alongside so the player can verify integrity at end-of-stream and surface a tampered-recording banner if it ever fails.

The audit timeline shows a chain-of-custody trail: `session.replicated` (the close metadata Rustion pushed), `recording.linked` (when BV first stored the pointer), and `rustion.audit.witness` (Rustion's own hash-chain entry for the same session). The replay window header surfaces all three so the operator playing back the cast knows the metadata stack underneath it.

### Trust establishment & enrolment lifecycle

```
   BastionVault                                  Rustion
   ────────────                                  ───────
1. operator clicks Enrol                            │
2. bvault rustion master export ──────submit──────▶ pending-authorities/
                                                     │  (inert; envelopes 403)
3. (waits)                                            │
                                              4. admin reviews via:
                                                 rustion authority list-pending
                                                 rustion authority approve --name <n>
                                              5. YAML moves authorities/<n>.yaml
                                                 hash-chain: authority.approved
6. next BVRG-v1 envelope ────────────────────────▶ verify, decrypt, accept
                                                 hash-chain: session.open

Periodic re-attestation (weekly):
   POST /v1/rustion/master/attest  →  refreshes attestation_renew_at

Revocation:
   delete target on BV side  →  signed `deenrol` envelope  →  Rustion tombstones
   delete authority on Rustion side  →  immediate refusal, BV picks up via health probe
```

Three guard-rails make this safe even if part of the mechanism fails:

- **Pubkey alone is not enough.** A master pubkey dropped into `authorities/<n>.yaml` by hand is still inert until paired with a `deployment_id` and `approved_at` — both stamped by Rustion at approval time, not by the submitter.
- **Deployment-id binding.** Every envelope carries the issuing BV's `deployment_id`. Rustion compares it against the value recorded at approval; a mismatch means the pubkey is being replayed from a *different* vault instance (cloning attack) and the envelope is refused. Operators rotating master keys re-submit through the same approval workflow — Rustion treats it as a key rotation, not a fresh enrolment, and updates `current_pubkey` while preserving `deployment_id`.
- **Tombstones outlive the record.** A deleted authority's `deployment_id` lives in `tombstoned/<n>.yaml` forever. Re-submitting the same `deployment_id` after a tombstone requires an admin's explicit `rustion authority untombstone <n>` action and writes both `authority.untombstoned` and `authority.approved` to the chain. This catches a compromised admin trying to silently re-add a previously-revoked vault.

### Renewal semantics

- TTL is set by the resource's policy (default 4h, max 12h), bounded above by the authority's `max_session_secs` on Rustion.
- The GUI fires renewal at `ttl - 60s`. If the user's session window is idle (`document.visibilityState === "hidden"` AND no input for 5 min), it skips renewal and lets the session expire — a soft idle-disconnect.
- `max_renewals` defaults to 3 (so default cap is 16h with 4h TTL). Hard cap on Rustion side regardless of envelope.
- A renewal that arrives *after* expiry is rejected; the operator must reopen, which lands a new audit trail.

### Failure modes

| Failure | Behaviour |
|---|---|
| Rustion control plane unreachable | Dispatcher walks to the next candidate (pinned-list mode) or picks a different healthy target (random-pool mode); the failed target is marked `down` after three strikes and excluded from selection until a probe succeeds again. If every candidate is unhealthy or rejects, Connect fails with `bastion_unavailable` and the per-target error list is surfaced. If `connect.transport=rustion-required` the user cannot fall back to direct. |
| All bastions in a resource's pinned list are `down` | Connect fails with `bastion_unavailable`; the GUI suggests "remove the pin to fall back to the global pool" only if the resource owner has permission to edit the profile. |
| Bastion goes `down` mid-session | The in-flight session drops on its own (TCP close); the session window shows "bastion lost" and offers Reconnect, which re-runs the dispatcher and may land on a different instance. |
| Master cert rotated but not yet enrolled on a Rustion | Rustion rejects with `unknown_authority`; GUI surfaces "re-enrol pending" and points to the rotation step. |
| Envelope replay (nonce seen) | Rustion logs `EnvelopeReplay` and rejects. BastionVault retries with a fresh nonce on transport-level errors only. |
| Recording webhook lost | BastionVault polls `GET /v1/sessions/{sid}/recording` for 24h after close; webhook is best-effort, polling is authoritative. |
| Operator force-terminates from BastionVault | `DELETE` envelope is signed and sent; on success the session window receives a Tauri event and shows a "terminated by admin" toast. |
| Rustion crashes mid-session | Session window detects socket close; ticket is already consumed so reconnect requires reopen. |

## Phases

### Phase 1 — Master cert + Rustion target registry + health monitoring — **Done**

- 0.7.12 — Module scaffold + storage + state machine in [`src/modules/rustion/`](../src/modules/rustion/). Routes: `LIST/POST /v1/rustion/targets`, `READ/WRITE/DELETE /v1/rustion/targets/{id}`, `READ /v1/rustion/targets/health`, `READ/WRITE /v1/rustion/master/config`, `READ /v1/rustion/master/pubkey`. Health-state machine ships with five unit tests covering the Unknown→Up promotion, Degraded landing on first failure, three-strikes-to-Down, one-success recovery, and stable-status no-change. Master-cert slot ships storage shape + config CRUD.
- 0.7.13 — Live HTTP pinger ([`src/modules/rustion/probe.rs`](../src/modules/rustion/probe.rs)) hitting `GET /v1/health` every 30s against every enabled target. Status transitions emit `rustion.target.health.changed`. New `POST /v1/rustion/targets/probe` (full sweep) and `POST /v1/rustion/targets/{id}/probe` (single-target test, returns fresh health record) for the enrolment wizard's test-connection affordance. `X-Rustion-Sig` header stays empty until Phase 2's master signing key lands; the nonce + authority headers are live.
- 0.7.14 — CLI subcommands (`bvault rustion target add|list|read|test|health|delete`, `bvault rustion master read|export`) and GUI Settings → Rustion Bastions section (target table with per-row health dot, enrolment wizard validating hybrid pubkey, Test Connection button, edit + delete modals, master-cert config + pubkey export panel). Tauri command wrappers + typed TS surface at [`gui/src/lib/rustion.ts`](../gui/src/lib/rustion.ts). Phase closed; master-cert issue/rotate ride on Phase 2's BVRG-v1 envelope crate.

- PKI slot for the master cert (issue, store, export pub).
- `rustion/` mount + `RustionTarget` CRUD on the API and GUI, supporting **multiple enrolled instances**.
- Settings → Rustion Bastions section with one-shot enrolment wizard and a per-row health dot.
- Rustion `GET /v1/health` endpoint + BastionVault background pinger (configurable interval, default 30s) with status cache, three-strikes-down / one-success-up debouncing, and `rustion.target.health.changed` audit events.
- CLI: `bastionvault rustion target add|list|test|health`, `bastionvault rustion master export`.
- Audit: `rustion.target.enrol`, `rustion.target.health.changed`, `rustion.master.issue`.
- No session traffic yet; this phase is plumbing + a green/red status indicator the dispatcher will key off in Phase 3.

### Phase 2 — BVRG-v1 envelope + Rustion control-plane scaffold — **Done** (BV 0.7.15 + Rustion 0.7.11)

- BV 0.7.15: `bv_crypto::bvrg::{build, verify}` + 11 round-trip + tamper tests + 4 adapter integration tests in `src/modules/rustion/envelope.rs`.
- Rustion 0.7.11: `crates/rustion-control-plane/` with envelope verify path, replay LRU + skew guard, axum `/v1/sessions` + `/v1/health` (sessions returns `501 not_implemented` after verify succeeds, exactly what Phase 2 calls for). 8 envelope tests + 5 replay tests + 2 cross-implementation tests proving `fips204`-produced ML-DSA-65 signatures verify under RustCrypto `ml-dsa` (the only crypto-library asymmetry between the two sides).

- `bastion-vault-crypto` gains the `bvrg::{build, verify}` helpers.
- New `rustion-control-plane` crate in `/Users/felipe/Dev/Rustion`. Authority YAML store + hot reload + `/v1/sessions` skeleton that verifies envelopes and returns canned `not_implemented`.
- Round-trip test from BastionVault → Rustion that a syntactically-correct envelope verifies and decrypts; no real session opens yet.

### Phase 3 — Session open + ticketed SSH proxy + dispatcher — **Done** (BV 0.7.17 + Rustion 0.7.13)

Shipped across 0.7.16/0.7.12 (dispatcher + session table + master stub) and 0.7.17/0.7.13 (KEM-pubkey schema + session-open route + ticket-auth module + GUI types):

- **BV dispatcher** (`src/modules/rustion/dispatcher.rs`) — pinned-list and random-from-healthy-pool modes, drops disabled/down/unknown targets with reason annotations, `should_advance` policy (transport/5xx advance, 4xx halt). 7 unit tests.
- **Rustion session table** (`crates/rustion-control-plane/src/session.rs`) — session record + single-use IP-bound 30s ticket, in-memory `RwLock<HashMap>` with capacity cap, TTL clamping, reap-expired sweep. 8 unit tests.
- **Rustion `/v1/sessions`** returns `201 Created` with the session bundle after envelope verification + replay protection. 3 in-process E2E integration tests.
- **BV master signing-key stub** (`src/modules/rustion/master.rs::get_or_init_signing_key`) — ephemeral hybrid keypair persisted at `rustion/master/signing-key` with a `stub: true` sentinel so Phase 9 can audit + replace.
- **`RustionTarget` schema gains `kem_public_key`** — separate ML-KEM-768 pubkey field on the registry record, threaded through the store, HTTP route, Tauri command, GUI enrolment wizard, and CLI `--kem-pubkey` flag.
- **BV `POST rustion/session/open` route** (`src/modules/rustion/session.rs::open_session_v2`) — pulls the registry + health cache, runs the dispatcher, walks candidates building a BVRG-v1 `open` envelope per try, POSTs at each candidate's `/v1/sessions`, advances on transport/5xx, halts on 4xx, returns the session bundle + dispatcher trail on success. Surfaces `503 bastion_unavailable` when no candidates qualify, `502 bastion_rejected` with per-target error list when every candidate refused.
- **BV `rustion_session_open` Tauri command** wraps the route; result type carries the session ticket bundle + the dispatcher's `bastion_selection` + `bastion_candidates_tried`.
- **GUI `ConnectionProfile.kind = "direct" | "rustion"`** discriminator on `gui/src/lib/types.ts`, with optional `bastions: string[]` (pinned ordered list, empty = global pool) and `recording: "always" | "off" | "input-redacted"` (strictest-wins override). Backwards-compatible — existing profiles without `kind` default to `"direct"`.
- **Rustion `rustion-ssh::ticket_auth`** — pure logic that consumes a `tkt_…` string + client IP via the SessionStore. All error paths collapse to `Invalid` from the caller's POV (no enumeration on the wire); detailed reason is logged at WARN with the ticket prefix sanitised to 8 hex chars for audit-chain correlation. 4 unit tests cover happy path, replay, wrong source IP, unknown ticket.

Phase 3.1 follow-up shipped in 0.7.19 (BV) + 0.7.15 (Rustion):

- **russh listener wire-up of `consume_ticket_for_login`** — `ServerHandler.auth_password` recognises `tkt_<32 hex>` passwords when wired up to a BV `SessionStore`, runs `consume_ticket_for_login`, stashes the matched session, and accepts auth. `ServerHandler::with_bv_session_store(store)` builder method opts into the path. `shell_request` learned a BV-session fast path that bypasses the user-store target ACL + interactive menu and dials the session's `target_host:target_port` with the decrypted `ssh-password` credential. Falls back to the classical user-store auth if the ticket lookup misses, so a Rustion user whose password happens to start with `tkt_` isn't locked out.
- **Recording authority field** — `SessionMetadata` gained `authority` + `correlation_id` fields. `connect_to_target_and_relay` accepts an `Option<(String, String)>` and stamps them on the asciicast `rustion.{authority,correlation_id}` header. `auth_method` records as `bv_ticket` for BV-mediated sessions, distinguishing them from `password` in SOC tooling. Recording start-on-first-byte was already the default (the recorder buffers until the proxy loop starts dialing the target); the only change was making the header carry the BV chain-of-custody fields.
- **E2E docker-compose scaffold** at [`tests/e2e/rustion-ssh/`](../tests/e2e/rustion-ssh/) — three-service stack (BV + Rustion + OpenSSH target) with a `run.sh` driver that walks the full pipeline cold-start → enrolment → probe → session-open → ticket-validated SSH to the target. **Revived and validated live in BV 0.10.16**: the compose file now builds both services from committed `Dockerfile`s (`bastion-vault:phase32` + `rustion:phase32`, build contexts `../../..` and `../../../../rustion`) — the earlier `phase31-scaffold` placeholder images are gone. The driver additionally exercises the connect-only credential-hiding path (a connect-only token is denied a direct secret read yet proxies a real SSH shell through the bastion). See also [`features/connect-only-access.md`](connect-only-access.md).

Phase 3.2 follow-up shipped in 0.7.20 (BV) + 0.7.16 (Rustion):

- **`ssh-key` and `ssh-cert` credential dialing** — `rustion-ssh::client` gained a `TargetCredential` enum (`Password | PrivateKey { pem, passphrase } | Cert { pem, cert_openssh }`) and a new `connect_to_target_with_credential` entry point. russh's `authenticate_publickey` (for keys) and `authenticate_openssh_cert` (for SSH-engine CA certs) are now both plumbed through. The BV-bypass branch in `shell_request` maps `session.credential.kind == "ssh-key"|"ssh-cert"|"ssh-password"` onto the right `TargetCredential` variant. Encrypted-key passphrase support waits for the BV connection-profile editor to surface the passphrase field; for now the dispatcher treats keys as unencrypted.
- **`Dockerfile`** at the root of both BastionVault and Rustion repos. Multi-stage builds (rust:1.82-bookworm builder + distroless cc-debian12 runtime) shipping the slim binaries. `tests/e2e/rustion-ssh/docker-compose.yaml` references both via `build:` so `docker compose up` builds the stack from source — no pre-built image dependency.

- Rustion `/v1/sessions` materialises a session, mints a ticket, returns connection coordinates.
- Rustion SSH listener accepts `ticket@<sid>` as the first auth step and proxies to the target with the decrypted credential.
- BastionVault's SSH session window takes `transport: rustion` and dials the bastion.
- **Dispatcher** (`src/modules/rustion/dispatcher.rs`): given a resource + profile, returns the candidate list — pinned ordered list from the profile, or a uniform random shuffle of all healthy enabled targets when the list is empty. Skips targets where `health.status != "up"`. Walks the list on transport / 5xx failures, surfaces per-target errors, and stops on auth failures (4xx).
- GUI Connection tab shows a live "Will try: …" preview that updates as health changes.
- `session.open` + `session.close` events on both sides include `bastion_selection` + `bastion_candidates_tried`; recording on but pointer not yet fetched.
- End-to-end: Linux target reachable through Rustion with multiple instances enrolled — random selection works in the empty-list case, ordered fallback works when one instance is down.

### Phase 4 — RDP through Rustion — **Done** (BV 0.7.18 + Rustion 0.7.14)

The session-open flow shipped in Phase 3 is protocol-agnostic — `rustion_session_open` accepts `target_protocol: "rdp"` and the Rustion `/v1/sessions` response routes the operator at the `rdp_advertise` SocketCoord. Phase 4 closes the remaining RDP-specific gap: the cookie-format ticket consumer on Rustion.

- **Rustion `rustion-rdp::ticket_auth`** (`crates/rustion-rdp/src/ticket_auth.rs`) — mirrors the SSH ticket-auth pattern. `consume_ticket_for_login(store, login)` extracts the `tkt_…` token from the RDP `mstshash=` cookie (tolerates `corp\user;tkt_…` style prefixes that some RDP clients prepend), consumes the ticket via the session store, returns the matched `Session` for the proxy loop to dial against. All error paths collapse to `Invalid` on the wire (no enumeration via the RDP error codes); detailed reason logged at WARN with the ticket prefix sanitised to 8 hex chars. 7 unit tests cover happy path, replay, wrong source IP, missing token, the corp-prefix tolerance, and the `extract_token` parser on edge cases.

### Phase 4.1 — RDP listener wire-up — **Done** (BV 0.7.21 + Rustion 0.7.17)

Mirror of Phase 3.1 for the RDP gateway. The pure `ticket_auth` module that landed in Phase 4 is now consumed by `rustion-rdp::proxy::handle_rdp_connection` at the X.224 connection-request stage:

- `RdpProxy` gained a `bv_session_store: Option<Arc<SessionStore>>` field and a `with_bv_session_store(store)` builder, identical in shape to `ServerHandler::with_bv_session_store` on the SSH side.
- After the X.224 CR is parsed, if the `mstshash` cookie contains a `tkt_…` substring AND the proxy was wired to a BV session store, the listener calls `consume_ticket_for_login` to resolve the ticket against the BV control plane.
- On success the proxy bypasses the local `auth_provider.authenticate()` and `authorize()` calls entirely — the BV control plane already proved the operator's identity and target authorisation when minting the ticket. `target_host` / `target_port` / `target_user` are pulled off the matched `Session`, the upstream is dialled at the BV-provided coordinates instead of whatever the cookie advertised, and an `AuditEvent::AuthSuccess { method: "bv-ticket" }` is logged.
- `SessionMetadata` on the RDP recording gets stamped with `authority` + `correlation_id` via `with_bv_authority(...)`, matching the SSH path. SOC tooling can join RDP recordings on the BV audit chain just like SSH ones.
- Failure paths fall through to the classical user-store flow so legacy operators whose mstshash payload happens to contain `tkt_` aren't locked out, and so non-BV-aware bastions degrade cleanly. All cross-cutting `rustion::usage` log lines carry an `auth_method = "bv-ticket"` field plus the authority+correlation when applicable.

### Phase 4.2 light — NTLMv2 primitives + CredSSP scaffolding — **Done** (BV 0.7.22 + Rustion 0.7.18)

Lays the foundation for bastion-driven upstream NLA when the BV envelope delivers an `rdp-password` credential.

- **`rustion-rdp::ntlmv2`** — full NTLMv2 message-construction layer:
  - `ntlmv2_hash(user, domain, password)` — NTOWFv2 per MS-NLMP §3.3.2 (MD4(UTF-16LE password) + HMAC-MD5).
  - `build_negotiate_message()` — NEGOTIATE_MESSAGE (type 1) wire bytes.
  - `parse_challenge_message(bytes)` — CHALLENGE_MESSAGE (type 2) parser with TargetInfo extraction + fail-closed on bad signature / wrong type / OOB.
  - `compute_responses(...)` — LMv2Response + NTLMv2Response (NTProofStr + temp blob) + SessionBaseKey per §3.3.2.
  - `build_authenticate_message(...)` — AUTHENTICATE_MESSAGE (type 3) with the six security-buffer fields laid out at the correct 72-byte payload_offset.
  - **Locked to MS-NLMP §4.2.4 reference vectors.** Three of four published worked-example outputs match exactly (NTOWFv2, NTProofStr, SessionBaseKey); the fourth (LMv2 last three bytes) appears to be a transcription error in the public spec — same HMAC-MD5 implementation that produces the spec's exact NTProofStr can't simultaneously produce a different LMv2. Three independent open-source implementations (Samba's `SMBOWFencrypt_ntv2`, impacket, sspi-rs) all compute the value our crypto produces. Documented in the test module.

- **`rustion-rdp::bv_credssp`** — bastion-side CredSSP driver scaffold:
  - `prepare_authenticate(challenge_bytes, user, domain, password, workstation, time, client_challenge) -> AuthInjection` runs the NEGOTIATE→CHALLENGE→AUTHENTICATE pair in-memory and returns the AUTHENTICATE_MESSAGE bytes plus the SessionBaseKey/ExportedSessionKey ready for the seal-key derivation.
  - `current_windows_time()` and `fresh_client_challenge()` helpers for live exchanges.
  - `BvCredsspError::SealingDeferred` and `BvCredsspError::UnsupportedKind` make the Phase 4.2-full gap explicit at the type level — callers can't silently dispatch into an incomplete code path.

- **Proxy wire-up** — `handle_rdp_connection` detects `bv_session.credential.kind`:
  - `rdp-password`: validates the envelope material is UTF-8, logs that CredSSP injection is prepared, and (for Phase 4.2 light) defers the actual sealed wire exchange to Phase 4.2-full.
  - `rdp-cert` (Phase 9.5): extracts + validates the smart-card material (`SmartCardCredsspParams::from_parts`) and dispatches to `bv_credssp_kerberos::drive_smartcard_credssp`, which under the `rustion_pkinit_sspi` build cfg drives the upstream Kerberos PKINIT / SPNEGO CredSSP with an sspi smart-card identity. Any other unknown kind still returns a clean `RdpError::Auth(...)` so the operator's GUI surfaces a clear error instead of hanging on a black RDP screen.
  - All `rustion::usage` TARGET_CONNECT lines carry `credential_kind` for SOC visibility.

12 new unit tests landed (8 in `ntlmv2`, 4 in `bv_credssp`). `cargo test -p rustion-rdp --features nla --lib` is green at 67 passing.

### Phase 4.2-full — CredSSP RC4 sealing + pubKeyAuth + simulated-Windows e2e — **Done** (Rustion 0.7.28 + BV 0.7.37, awaiting live Windows VM)

The bastion-driven CredSSP injection driver is now wire-complete: it builds the AUTHENTICATE message, encrypts the random session key, derives sign+seal keys per direction, seals/signs `pubKeyAuth` and `authInfo`, and verifies the upstream's pubKeyAuth reply. All three legs share one continuous RC4 keystream per direction. End-to-end-tested against an in-process Windows responder; live-Windows validation is queued for the next CI VM availability.

**Shipped — `rustion-rdp::ntlmv2_seal`** (new module, +209 LoC, 7 unit tests including RFC 6229 RC4 KAT):

- `sign_key(esk, magic)` + `seal_key(esk, magic)` — MS-NLMP §3.4.5.2 + §3.4.5.3. The four magic constants `CLIENT_SIGNING_MAGIC` / `SERVER_SIGNING_MAGIC` / `CLIENT_SEALING_MAGIC` / `SERVER_SEALING_MAGIC` match the C-string literals in the spec (including the trailing `\0`).
- `Rc4` streaming cipher + `rc4_once(key, data)` one-shot helper. KAT-tested against RFC 6229 `Key = 0102030405`.
- `SealState { sign_key, rc4, seqnum }` — per-direction state. `.seal(plaintext)` produces `NTLMSSP_MESSAGE_SIGNATURE_v2 (16B) || ciphertext`, advancing the seqnum and continuing the RC4 keystream. `.unseal(blob)` is the inverse and verifies the HMAC-MD5 checksum.

**Shipped — `rustion-rdp::bv_credssp` rewrite** (Layer 1 stateless primitives + Layer 2 orchestration handle):

- `prepare_authenticate(...) -> AuthInjection { auth_message, session_base_key, exported_session_key, seal_c2s, seal_s2c }`. Generates a fresh `ExportedSessionKey`, encrypts it under `KeyExchangeKey = SessionBaseKey` (extended-session-security path) to produce `EncryptedRandomSessionKey`, and returns ready-to-use sealing handles.
- `SealedCredsspSession::seal_pub_key_auth(spki_der)` / `verify_pub_key_auth(reply, expected_spki)` — implements the MS-CSSP §3.1.5 "+1 first byte" pubKeyAuth contract.
- `SealedCredsspSession::seal_auth_info(ts_credentials_ber)` — third-leg sealed authInfo.
- `encode_ts_password_creds(domain, user, password)` — BER-encodes `TSCredentials → TSPasswordCreds` per MS-CSSP §2.2.1.2 (cred_type=1, UTF-16LE strings). Round-trip-tested against the existing inbound BER parser in `crate::nla`.

**Shipped — `rustion-rdp::tests::credssp_e2e`** (substitute for a live Windows VM):

- `MockServer` simulates a Windows NLA responder: emits `CHALLENGE_MESSAGE`, ingests `AUTHENTICATE_MESSAGE`, re-derives the NTOWFv2 from the known password, asserts the bastion's `NTProofStr` matches, recovers `ExportedSessionKey` via RC4 inverse, and builds matching seal states.
- `full_credssp_exchange_against_simulated_windows` — full three-leg round trip: NEGOTIATE → CHALLENGE → AUTHENTICATE + sealed pubKeyAuth + sealed TSCredentials. Asserts the server recovers the exact `TSCredentials` byte sequence the bastion sealed.
- `pub_key_auth_reply_rejects_unrelated_spki` — verifies the +1 transform check catches MITM-style mismatches.
- `wrong_password_breaks_at_the_server` — pins the failure mode when the bastion holds the wrong password (in prod: upstream replies with errorCode-bearing TSRequest).

**Shipped — `rustion-rdp::proxy` log+error message refresh** — the BV credential dispatch now logs Phase 4.2-full status instead of "deferred to Phase 4.2-full". `rdp-cert` still routes to its dedicated error string (smart-card PKINIT/SPNEGO is its own separate track).

**What's NOT in this slice (deliberately):**

- **Live Windows VM validation.** The simulator covers the protocol logic but does not exercise edge cases that a real Server 2022/2025 implementation might have (timing variance, error-code dialect, NTLMv2 with channel binding, etc.). The user has indicated a VM will be provided later; first such disagreement found against a live VM should grow a fresh failing test in `credssp_e2e.rs` before the fix lands.
- **Transport hookup.** The driver is callable end-to-end from `bv_credssp` primitives, but `proxy::handle_rdp_connection` does not yet drive a live upstream TLS socket through the three legs — the call site logs that the driver is "ready" while the underlying tokio I/O stitching ships in the live-Windows integration pass (it's a thin wrapper around `crate::nla::read_raw_ts_request` + `TsRequest::encode` and is mechanical once a real responder is on the wire).
- **`rdp-cert` smart-card.** Lands in Phase 9.5 (below), not this slice.
- **Restricted Admin mode.** Out of scope.

**Original Phase 4 acceptance criteria** — kept for reference:
- Rustion RDP gateway accepts the same ticket protocol. ✅ shipped Phase 4
- BastionVault's RDP session window takes `transport: rustion`. ✅ shipped Phase 4
- ironrdp client connects to the bastion's TLS+PQC listener instead of the target; the target side is Rustion's existing RDP proxy. ✅ shipped Phase 4.1
- CredSSP / NLA tested with Secret, LDAP, and PKI credential sources. ✅ Secret (this slice, simulated Windows). LDAP/PKI follow the same envelope shape — they only need the upstream signal that NLA succeeds, which the driver now produces. PKI smart-card client-cert delegation is its own track.

### Phase 5 — Renewal + forced termination — **Done** (BV 0.7.23 + Rustion 0.7.19)

- **Rustion `SessionStore`** gained `renew_from_envelope(verified, sid, max_session_secs, now)` and `kill_from_envelope(verified, sid, now)`. Renewal enforces a `max_renewals` budget stamped at open time, rejects mismatched `correlation_id` (the binding check that ties a renewal to a specific operator-session), clamps the extension to the authority cap, and refuses already-killed sessions. Kill marks `killed_at = Some(now)`, drops the ticket-index entry so any in-flight consume rejects, and is idempotent-erroring on second invocation. `consume_ticket` now also rejects when the session is killed mid-flight. 8 new unit tests in `session::tests` cover budget exhaustion, correlation-id mismatch, wrong-op envelope rejection, authority-cap clamping, ticket invalidation on kill, and the renew-after-kill ordering.
- **Axum routes**: `POST /v1/sessions/:sid/renew` and `DELETE /v1/sessions/:sid`. Both run through the same authority/replay/signature gates as `/v1/sessions` via a new `verify_and_replay` helper. Success returns `{session_id, expires_at, renewals_used, max_renewals}` (renew) or `{session_id, terminated_at}` (kill). Error mapping: `404 session_not_found`, `409 renewal_budget_exhausted`, `409 correlation_id_mismatch`, `409 session_already_terminated`, `409 envelope_replay`. New `tests/session_renew_kill_e2e.rs` covers a full open → renew → kill round trip plus the three primary failure modes — 4 axum integration tests, all green.
- **BV-side**: `session::renew_session` + `session::kill_session` in `src/modules/rustion/session.rs` build the renew/kill envelopes via the existing `envelope::build_renew` / `envelope::build_kill` helpers and POST/DELETE at the specific bastion that opened the session (no dispatcher walk — renew/kill always go to one known target). New HTTP routes `POST rustion/session/renew` + `POST rustion/session/kill`, new audit lines `session.renew` / `session.terminate`, new Tauri commands `rustion_session_renew` / `rustion_session_kill`.
- **`SessionOpenResponse` now carries `correlation_id`** so the GUI knows what to pass to subsequent renew/kill calls. The Tauri command + TypeScript `RustionSessionOpenResult` were updated in lock-step.
- **GUI surface**: new React hook `useRustionSessionLifecycle({session, isIdle, autoRenewEnabled, renewLeadSecs, extendSecs})` in `gui/src/hooks/`. The hook fires auto-renew at `expires_at - 60s` (configurable), skips when the operator's terminal has been idle, halts when the renewal budget is exhausted, and exposes `renew()` + `kill()` for manual buttons. Drop-in for any Connection Window — currently no consumer because the BV-side connection window for Rustion-mediated sessions is still scaffolding.

Phase 5.1 — master-cert rotation (co-signed envelope accepted during the old key's `not_after` grace window) — is tracked separately under Phase 9 since it shares the enrolment + re-attestation surface area.
- Master-cert rotation: co-signed envelope, accepted by enrolled Rustions until the old key's `not_after`.

### Phase 6.1 — Recording sidecar baseline — **Done** (BV 0.7.24 + Rustion 0.7.20)

The chain-of-custody artifact BV needs to attach a recording to the right audit-chain entry, without parsing the recording itself.

- **`rustion-recording::sidecar`** new module:
  - `RecordingSidecar` wire-format struct matching `docs/bastionvault-integration.md` §Recording handoff verbatim: `recording_id`, `session_id`, `authority`, `format` (`asciicast` | `rdp-rec` | `smb-log`), `sha256`, `size_bytes`, `started_at`, `finished_at`, `target_host`, `target_user`, `correlation_id`.
  - `from_handle_and_metadata(handle, metadata, session_id)` — streams the recording file through sha2 (64 KiB buffered, bounded memory for multi-GB recordings) and merges in the session metadata.
  - `write_next_to(recording_path)` — drops `<rec>.json` next to `<rec>.cast` / `<rec>.rdp-rec`.
  - `read(path)` — round-trip for the future `GET /v1/sessions/{sid}/recording` endpoint (Phase 6.2).
- **SSH + RDP proxies** both emit the sidecar at `recorder.finish()` time, right after the recording-index entry is updated. Best-effort — a failed sidecar write WARNs but never sinks the user's session. `rustion::usage` emits `RECORDING_READY` carrying `session_id`, `recording_id`, `authority`, `correlation_id`, and `size_bytes` for SOC observability.
- For classical (non-BV) sessions the sidecar lands with empty `authority` + `correlation_id` strings — the `serde(default)` tags keep parsing clean either way.
- **5 unit tests** in `sidecar::tests` (extension swap, sha256 known-vector, BV round-trip, classical session empty-fields, protocol→format mapping).

### Phase 6.2 — Recording webhook + receiver + index — **Done** (BV 0.7.25 + Rustion 0.7.21)

The signed-handoff loop between Rustion and BV — sidecar payload travels with a detached hybrid signature, both endpoints reject classical-only as a downgrade, and BV persists the resulting recording entry on its side of the audit chain.

- **`rustion-control-plane::webhook`** new module:
  - `WebhookSigningKey` (Ed25519 + ML-DSA-65 keypair, generate or load-from-bytes) and `WebhookVerifyingKey` (verify path mirror).
  - `sign_header(body) → "ed25519=<base64> mldsa65=<base64>"` — signs `sha256(body)` with both halves; same hash-then-sign shape as the BVRG-v1 envelope path.
  - `deliver(client, url, body, signature_header)` one-shot POST helper for proxies to call after the sidecar lands.
  - `verify_header(header, body)` rejects malformed headers, classical-only downgrades, and pubkey-length mismatches via `WebhookError`.
  - 8 unit tests: round trip, body tamper, wrong-pubkey, malformed header, classical-only downgrade, from-bytes round trip, token-order parsing.
- **`GET /v1/sessions/{sid}/recording`** on the axum router serves the sidecar JSON for the 24h pull-fallback window. `ControlPlaneState.recordings_base_dir` configures the lookup root; absent → endpoint responds 404 with `recording_storage_disabled`.
- **`AuthorityRecord.recording_webhook_url`** added to the per-authority record so the orchestration layer knows where to POST.
- **BV side**:
  - `src/modules/rustion/webhook_verify.rs` — mirror of the Rustion verifier in-tree, validated against the same crate's signer with 4 round-trip tests (including classical-only downgrade rejection). Uses `fips204` (already a BV dep for outbound BVRG-v1 signing) for the PQC half so no extra crypto crate.
  - `src/modules/rustion/recordings.rs` — `RecordingsStore` over `rustion/recordings/<rid>` under the system view. `RecordingEntry` carries every field from the sidecar plus `bastion_id`, `received_at`, and `delivery_mode` ∈ {`webhook` | `pull` (Phase 6.3)}.
  - New routes:
    - `POST rustion/webhooks/recording-ready` — verifies the X-Rustion-Signature against the pinned `RustionTarget.public_key`, parses the sidecar, persists the entry, emits `audit::RECORDING_LINKED`.
    - `GET rustion/recordings` — list known recording ids.
    - `GET rustion/recordings/<rid>` — fetch one entry.

### Phase 6.3 — Retry loop + pull-fallback + recording surface — **Done** (BV 0.7.26 + Rustion 0.7.22)

Closes the operational handoff loop: webhooks survive transient failures with bounded backoff, BV can force-pull a missed recording, and the GUI has the API surface it needs to query the recordings index.

- **`rustion-control-plane::webhook::deliver_with_retry`** — wraps the one-shot `deliver()` with an exponential-backoff schedule. `RETRY_DELAYS_SECS = [30, 60, 240, 600, 900]` matches the spec's "5 retries over ~30 min" target (1830 s total = 30m 30s). Each attempt logs `rustion::usage` `RECORDING_WEBHOOK_RETRY` (failure) or `RECORDING_WEBHOOK_DELIVERED` (success) so SOC tooling can see the delivery shape. The inner `deliver_with_retry_impl` accepts a `sleep_fn` for fast deterministic tests; 2 new unit tests cover schedule total + walking-then-giving-up against `127.0.0.1:1`.
- **BV `recordings::pull_recording(targets, recordings, bastion_id, session_id)`** — GETs the bastion's `/v1/sessions/{sid}/recording` endpoint, parses the sidecar, stores it with `delivery_mode = "pull"`. Signature check is *not* required on this path because the sidecar comes back over the bastion's TLS-pinned channel (no third-party hop the way the webhook has). Emits `audit::RECORDING_LINKED` with `mode=pull`.
- **New BV HTTP route**: `POST rustion/recordings/pull` driving the pull helper. Operator-triggered or scheduler-driven.
- **Tauri commands**: `rustion_recordings_list`, `rustion_recording_read`, `rustion_recording_pull`. Typed TypeScript wrappers in `gui/src/lib/rustion.ts`. The Connection Window can now display "Recording: ready" once the entry lands, and offer a "Refresh from bastion" button that calls `rustionRecordingPull`.

### Phase 6.4 — Cron + bytes endpoint + proxy emit glue — **Done** (BV 0.7.27 + Rustion 0.7.23)

Closes the operational handoff loop fully — the BV cron pulls missed recordings on schedule, Rustion serves recording bytes for playback, and the SSH/RDP proxies actually fire webhook deliveries on `recorder.finish()`.

- **BV `recordings::PendingRecording` + `pending_view`** — every successful `session/open` now stamps a pending-recording marker carrying `session_id`, `bastion_id`, `correlation_id`, `expected_by = expires_at + 5 min`. Webhook delivery and pull-fallback both clear the marker.
- **BV `poller` module** — detached background task spawned at boot from `core.rs` alongside `rustion::probe::start_pinger`. Mirrors the pinger's `tokio::time::interval` shape; ticks every `TICK_INTERVAL` (1 h); walks the pending view and calls `pull_recording` for every entry past its `expected_by` deadline. Entries past `MAX_RETENTION = 24 h` are dropped as unrecoverable (operators can still pull manually via `POST rustion/recordings/pull`).
- **Rustion `webhook::WebhookEmitter`** — shared handle that looks up the per-authority webhook URL via the `AuthorityStore`, signs the sidecar bytes, and spawns a detached `deliver_with_retry` task. Emitter is `Arc<>`-shared, constructed once at `rustion-server` startup; injected into both `SshProxy::with_webhook_emitter` and `RdpProxy::with_webhook_emitter`.
- **SshProxy / RdpProxy / ServerHandler** wiring — proxies pass the emitter down to `connect_to_target_with_credential_and_relay` (SSH) / `handle_rdp_connection` (RDP). After the sidecar lands and `RECORDING_READY` fires, the relay serialises the sidecar struct via `serde_json::to_vec` and calls `emitter.spawn_delivery(authority, body)`. Classical (non-BV) sessions skip the call cleanly (empty authority).
- **Rustion `GET /v1/recordings/:rid/blob`** — serves the recording artifact bytes for in-GUI playback. Maps `rec_<sid_suffix>` → `<sid>.cast` / `<sid>.rdp-rec` via the per-session sidecar. Returns `X-Recording-SHA256` + `X-Recording-Format` headers so the player can verify integrity before rendering.

### Phase 6.5 — GUI Recordings page + asciicast playback + `.rdp-rec` summary — **Done** (BV 0.7.28)

Phase 6 is now fully closed end-to-end on the recording handoff loop. SSH recordings play inline; RDP and SMB recordings surface a metadata view + download with the upstream-bitmap decoder tracked as its own UI engineering project.

- **BV recording-bytes proxy**: `GET rustion/recordings/<rid>/blob` → routes through `recordings::fetch_blob` to the bastion's `GET /v1/recordings/<rid>/blob`, returns the bytes base64-wrapped (JSON-friendly Tauri boundary). New Tauri command `rustion_recording_blob(rid) → RustionRecordingBlob` + typed TS wrapper.
- **`/recordings` route + sidebar entry**: new `RecordingsPage` route. Lists every `RustionRecordingEntry` from the recordings index with format/delivery/search filters; surface bastion-pull-force from the same page (operator types `bastion_id` + `session_id` and clicks "Pull from bastion").
- **`RecordingPlayerModal`**: opens on row click. Loads bytes via `rustionRecordingBlob`, decodes base64 → `Uint8Array`, dispatches to a format-specific renderer.
- **`AsciicastPlayer`** (SSH): native xterm.js renderer (no third-party `asciinema-player` dep — saves ~80 KB in the bundle). Parses asciicast v2 (header line + `[time, type, data]` events), drives an xterm with the spec-mandated `cols`/`rows`, schedules writes off `performance.now()` with a 200ms tick cap.
- **`RdpRecSummary`** (RDP): walks the `.rdp-rec` frame stream natively in TS — magic `"RREC"` check + JSON header parse + `(ts:u64 + type:u8 + len:u32 + payload)` iteration. Surfaces header, graphics/keyboard/mouse event counts, total duration. Inline visual replay is gated on a real RDP bitmap-update codec (MS-RDPBCGR slow-path bitmap, raster ops, NSCodec) — that's a multi-week protocol-decoder project on its own track, called out in the page UI as "future enhancement". The download button hands the operator the raw `.rdp-rec` for external viewers.
- **`SmbLogSummary`** (SMB): plain-text op log preview + download.

### Phase 7.1 — Policy data model + resolver + global/bastion-groups CRUD — **Done** (BV 0.7.29)

The foundation layer of the four-tier policy: data model, storage, the effective-policy resolver, and the global + bastion-groups CRUD surface (HTTP + Tauri + TS).

- **`src/modules/rustion/policy.rs`** new module:
  - **Enums**: `Transport ∈ {Direct, RustionPreferred, RustionRequired}`, `Recording ∈ {Off, InputRedacted, Always}`, `Selection ∈ {Ordered, Random}`.
  - **Per-tier struct** `PolicyTier { transport, bastions, bastion_group, recording, lock }` — all `Option` so undefined knobs fall through.
  - **Wrappers** `GlobalPolicy`, `TypePolicy`, `AssetGroupPolicy { priority }`, `ResourcePolicy`.
  - **`BastionGroup { name, members[], selection, description, timestamps }`**.
  - **`resolve(global, type_, asset_groups[], resource) → EffectivePolicy`** implements the spec's resolution rules:
    - `transport`: **most-restrictive wins** (rank: required > preferred > direct).
    - `recording`: **strictest wins** (rank: always > input-redacted > off).
    - `bastions` / `bastion_group`: **nearest-defined-tier wins**.
    - **Asset-group priority**: high priority wins via low-first overwrite ordering.
    - **Locking**: a tier with `lock = true` snapshots its knobs; lower tiers may match-or-strengthen but never weaken. Violations surface as `EffectivePolicy.lock_violation = Some(LockViolation { locking_tier, field, detail })`.
  - **`PolicyStore`** with five storage views (`rustion/bastion-groups/`, `rustion/policy/global`, `rustion/policy/type/`, `rustion/policy/asset-group/`, `rustion/policy/resource/`) and CRUD helpers for each.
  - **8 unit tests**: default-when-no-tiers, resource-can-raise-transport, transport-most-restrictive-wins, lock-prevents-weakening-transport, recording-strictest-wins, locked-recording-prevents-off-override, bastions-nearest-tier-wins, asset-group-priority-breaks-ties.
- **HTTP routes**:
  - `GET/PUT rustion/policy/global` — root-gated.
  - `GET rustion/bastion-groups` (list) + `POST rustion/bastion-groups` (create).
  - `GET/PUT/DELETE rustion/bastion-groups/<name>` (CRUD).
- **Audit constants** already existed in `audit.rs` from Phase 1 spec — `POLICY_GLOBAL_UPDATE`, `POLICY_TYPE_UPDATE`, `POLICY_ASSET_GROUP_UPDATE`, `POLICY_RESOURCE_UPDATE`, `BASTION_GROUP_UPDATE`. The new handlers emit `POLICY_GLOBAL_UPDATE` and `BASTION_GROUP_UPDATE` (the other three light up in Phase 7.2 alongside the per-tier editors).
- **Tauri commands + TS wrappers**: `rustionPolicyGlobal{Read,Write}`, `rustionBastionGroup{List,Read,Create,Update,Delete}`.

### Phase 7.2 — Per-tier CRUD + session/open resolver + Settings UI + migration — **Done** (BV 0.7.30)

Brings the four-tier policy from "data model + global CRUD" up to a usable governance surface: type/AG/resource CRUD, `session/open` consults the resolver, the migration action ships, and a Settings panel lets root + admins configure the deployment policy.

- **HTTP routes** for the three remaining tiers:
  - `GET/PUT/DELETE rustion/policy/type/<type_name>` — admin-gated.
  - `GET/PUT rustion/policy/asset-group/<asset_group_id>` (with `priority`) — admin or group-owner.
  - `GET/PUT rustion/policy/resource/<resource_id>` — resource owner. Refuses `lock=true` from this tier (per-resource cannot lock). Refuses a write that would weaken a lock from a higher tier (probe-resolve at write time).
  - `POST rustion/policy/force-rustion?confirm=true|false` — Root-only migration: flips global to `transport=rustion-required + lock=true`. Without `confirm` returns a diff preview.
- **8 new Tauri commands + TS wrappers**: `rustionPolicyType{Read,Write,Delete}`, `rustionPolicyAssetGroup{Read,Write}`, `rustionPolicyResource{Read,Write}`, `rustionPolicyForceRustion`.
- **`session/open` resolver wiring** in `src/modules/rustion/mod.rs::handle_session_open`:
  - Loads the global tier from `PolicyStore`.
  - Calls `policy::resolve(global, None, &[], None)` — Phase 7.3 wires per-resource / asset-group / type lookups once the editor surface attaches them to resource records.
  - Refuses on `lock_violation` (403).
  - Refuses on `transport=rustion-required` when no bastions are enrolled (403 `rustion-required policy: no bastions enrolled`).
  - Overrides caller-supplied `bastions` with the policy's pinned list or the resolved bastion-group's members when those are set (so a policy-pinned group can't be silently bypassed).
  - Forces the `recording` field to the resolver's value (strictest-wins).
  - Stamps `policy_transport`, `policy_transport_source`, `policy_recording`, `policy_recording_source`, `policy_bastions_source`, `policy_locked_by` on the response so the GUI can show the resolution chain.
- **Settings → Rustion → Policy panel**: new `RustionPolicyPanel` component mounted under the existing "Rustion" tab alongside `RustionBastionsTab`. Three cards: Global Policy editor (transport / recording / bastions / bastion_group / lock), Bastion Groups CRUD (list + create/edit/delete modals with member list + selection mode + description), and "Force all Connect through Rustion" with preview→confirm dry-run flow.
- **Audit emission**: `POLICY_TYPE_UPDATE`, `POLICY_ASSET_GROUP_UPDATE`, `POLICY_RESOURCE_UPDATE` now light up at their respective write sites. `POLICY_GLOBAL_UPDATE` doubles as the audit event for the force-rustion migration.

### Phase 7.4 — GUI Connect honours Rustion policy — **Done** (BV 0.8.21 SSH, BV 0.8.22 RDP, BV 0.8.23 lifecycle)

Closes the gap left by Phase 7.3: the policy resolver was wired into `session/open`, but the in-app Connect button never invoked `session/open`. It dialled the resource directly regardless of the per-resource transport setting, so a `rustion-required` policy was effectively cosmetic for clicks from the GUI.

- **`POST rustion/policy/effective`** (server) -- New read-only resolver endpoint that returns the effective policy verdict (`transport` / `bastions` / `bastion_group` / `recording` / `locked_by` / `lock_violation`) for a given `resource_id` + `resource_type` + `asset_group_ids` without opening a session. Reuses `policy::resolve` and expands `bastion_group` membership to a concrete bastion list. The GUI Connect path calls this before deciding to dial.
- **`rustion_policy_effective` Tauri command** -- Thin wrapper over the new endpoint.
- **`gui/src-tauri/src/commands/connect.rs` -- SSH Connect routes through Rustion when policy requires.** After resolving the credential, the handler consults the effective policy:
  - `transport=rustion-required` with an ssh-password credential → calls `rustion/session/open` (passing the policy hints) and dials the returned `bastion_host:bastion_port` as user `operator` with the ticket as the SSH password. The bastion proxies to the real target.
  - `transport=rustion-preferred` with bastions available + ssh-password → same path, falls back to direct on rustion failure.
  - `transport=rustion-required` with a non-ssh-password credential (private-key / certificate) → fail closed with explanatory error. Only ssh-password is wired through the bastion proxy today (matches the rustion-ssh e2e harness).
  - `transport=direct` or empty → existing direct dial.
  - Lock violation surfaced from the resolver → fail closed.
- **`gui/src-tauri/src/commands/connect.rs` -- RDP Connect routes through Rustion when policy requires (BV 0.8.22).** Same shape as SSH:
  - `rustion-required` + rdp-password → `rustion/session/open` with `target_protocol=rdp` / `credential_kind=rdp-password`; dials bastion `host:port` with the ticket carried in the X.224 routing-token slot as `mstshash=tkt_<hex>` (via `NegoRequestData::routing_token`). The bastion consumes the ticket at the Connection Request stage, skips client-side NLA, and drives upstream CredSSP itself with the envelope's credential (Phase 4.2-full bv_credssp injection driver).
  - `rustion-preferred` + bastions + rdp-password → same path, falls back to direct on Rustion failure.
  - `rustion-required` + smart-card (rdp-cert) → **routes through the bastion (Phase 9.5).** The resolver sends `credential_kind=rdp-cert` with the certificate DER (`credential_material`) + DER private key (`credential_key`) + PIN (`credential_pin`); the bastion drives upstream Kerberos PKINIT / SPNEGO CredSSP with an sspi smart-card identity. Direct dial with the PIV emulator still works on `direct` / `preferred`.
- **`session::rdp::RdpOpenArgs::routing_token`** — new `Option<String>` plumbing the ticket cookie into `ConnectorConfig::request_data`.
- **Session lifecycle wired into the spawned window (BV 0.8.23).** The host stashes `{session_id, bastion_id, bastion_name, correlation_id, expires_at, max_renewals, protocol}` in `AppState::rustion_session_bundles` keyed by the SSH/RDP session token. A new `session_rustion_info` Tauri command surfaces it. The window mounts a shared `RustionSessionChip` that calls `useRustionSessionLifecycle`, auto-renewing at `expires_at − 60s` and surfacing manual Renew + Terminate buttons + a live TTL countdown + the `used / max` renewal budget. Direct sessions render no chip.
- **Limitations carried into a follow-up:** ~~bastion host-key / TLS pinning is not yet enforced~~ — **resolved in Phase 9.4 (below).** ~~rdp-cert (smart-card) through Rustion remains blocked on the bastion's separate PKINIT/SPNEGO path~~ — **plumbed in Phase 9.5 (below); the sspi Kerberos engine is build-gated (`rustion_pkinit_sspi`) and live-AD validation is pending.**

### Phase 9.4 — Bastion host-key / TLS pinning in the GUI dialler — **Done** (cross-repo: BV + Rustion listener schema v2)

Closes the transport-authentication gap left open by Phase 7.4: the operator's client dialled the bastion's SSH proxy with an empty host-key pin (unpinned TOFU) and its RDP gateway with no TLS certificate verification at all (`ironrdp_tls` uses a no-op verifier). The whole point of the bastion is to be the network choke-point, but nothing authenticated the hop *to* it — a MITM on the operator→bastion segment could impersonate the bastion and harvest the one-shot ticket. This phase pins the bastion's transport identity end-to-end.

- **Rustion — persistent RDP TLS certificate.** The RDP gateway cert was regenerated on every boot (`generate_rdp_tls_config`), so its fingerprint could never be pinned. It is now load-or-generate against `server.rdp_tls_cert_path` (default `<config_dir>/rdp_tls_cert.der`, key at the sibling `.key`, `0600`), mirroring the existing persistent SSH host key. A read-only config dir logs a loud warning rather than failing — but pinning then can't be stable, which the warning says explicitly.
- **Rustion — listener schema v2.** `GET /v1/listeners` grows a per-protocol `pin` field: the SSH proxy's OpenSSH host-key fingerprint (`SHA256:<base64>`) and the RDP gateway's TLS leaf digest (`sha256:<hex>`). `schema_version` bumps to `2`; the field is `skip_serializing_if` empty so a bastion that doesn't co-locate a proxy (or an older client) sees exactly the old shape. Threaded through `BootstrapParams` → `ControlPlaneState`.
- **BastionVault — store the advertised pins.** `RustionTarget` grows `ssh_host_key_fingerprint` + `rdp_tls_pin_sha256` (both `#[serde(default)]`, read-old/write-new safe). Populated by the existing listener-discovery path (`set_listener_info`, fired at enrolment and on manual refresh). A pin *change* on re-discovery is logged as a warning (a rotated host key). Surfaced on the target read response and shown as green "SSH host-key pinned" / "RDP TLS pinned" badges (amber "unpinned" when the bastion advertised none) on the Settings → Rustion Bastions row.
- **BastionVault — pin the dial.** `resolve_bastion_dial_coords` now returns the protocol's pin alongside host/port, carried on `ConnectRoute::Rustion` as `bastion_pin`.
  - **SSH:** the pin becomes the `host_key_fingerprint` fed to the existing `HostKeyHandler`, which already fails closed on mismatch. Empty pin (pre-v2 bastion) logs an unpinned-TOFU warning and proceeds — matching the direct path's posture for an unset pin.
  - **RDP:** `RdpOpenArgs::tls_pin_sha256` carries the pin; after the TLS upgrade the dialler re-encodes the observed leaf to DER, SHA-256s it, and compares (prefix/case-tolerant). Mismatch aborts *before* any session bytes flow. Because the RDP TLS layer performs no CA validation, this pin is the sole authentication of the bastion's RDP TLS identity.
- **Trust model:** trust-on-first-use at enrolment (the operator validates reachability + records the fingerprint), pinned thereafter. A later fingerprint flip is surfaced (warning + badge) and, for a value the operator hasn't re-synced, the dialler refuses — deliberately fail-closed, with an error that names the fix (re-run listener discovery after an intentional rotation).
- **Tests:** Rustion — RDP cert persistence + stable fingerprint across reloads, `listener_info_from` pin passthrough + `skip_serializing_if`. BV — listener v1/v2 wire-compat decode, RDP pin match (prefix/case tolerance, empty-pin rejection).

### Phase 9.5 — Smart-card RDP (`rdp-cert`) through the bastion via Kerberos PKINIT / SPNEGO — **Done (plumbing); sspi engine build-gated, live-AD pending** (cross-repo: BV + Rustion)

Closes the last `rustion-required` fail-closed gap: a resource pinned to a bastion whose credential source is a PKI smart-card cert. Smart-card logon can't ride NTLMv2 (which the `rdp-password` driver hand-rolls) — the target authenticates the operator via **Kerberos PKINIT** (the cert + private key drive an AS-REQ to the domain KDC), and the resulting AP-REQ rides inside a **SPNEGO** token in the CredSSP `negoTokens`. Rather than hand-roll that, the bastion delegates to **sspi-rs** — the exact engine the GUI's *direct* smart-card path already proves against real Active Directory.

- **Envelope — carry the smart-card material.** The BVRG-v1 `rdp-cert` credential now puts the certificate DER in `material` and seals the DER private key + PIN (+ optional domain) into `credential.extra` (`build_credential_extra` in `envelope.rs`). BV's `session/open` grows `credential_key` (base64 DER) / `credential_pin` / `credential_domain` request fields; the GUI RDP resolver populates them from the resolved `SmartCardCredential` (cert + key + PIN it already mints for the direct path) instead of failing closed.
- **Rustion — expose the material.** `SessionCredential` grows `rdp_cert_{der,key,pin,domain}()` accessors reading `material` + the `extra` CBOR map (mirroring `openssh_cert()`). The private key + PIN live in `Zeroizing` buffers and are decrypted only inside the Rustion process.
- **Rustion — the driver (`bv_credssp_kerberos`).** `SmartCardCredsspParams::from_parts` extracts + validates the material and derives the `TERMSRV/<host>` SPN (port/bracket-stripped). `drive_smartcard_credssp` builds an sspi smart-card `Credentials` + `CredSspClient` in `Negotiate(Kerberos)` mode (mirroring ironrdp-connector's `credssp::init`) and runs the TSRequest exchange over the upstream socket, resolving KDC lookups through sspi's async network client. The RDP proxy's credential dispatch replaces the old `rdp-cert` reject with this path.
- **Build gating.** The sspi Kerberos engine is compiled under the opt-in `pkinit` cargo feature (`--features rustion-rdp/pkinit`) so the default build stays free of the heavy sspi/picky fork stack. The default build extracts + validates the material and fails closed with a precise "engine not built" error.
- **rc.18 crypto-chain migration (landed + validated).** Enabling the engine required aligning Rustion's RustCrypto chain with the sspi/picky forks: the vendored russh submodule moved to the fork `fix-deps` branch (ecdsa rc.18 / elliptic-curve rc.32 / p256/384/521 rc.9 / rsa rc.18 / curve25519-dalek pre.6 / aes-gcm rc.4, keeping the channel-deadlock fixes); the PQC crates bumped to stable `ml-dsa` 0.1.x / `ml-kem` 0.3.x (matching `pkcs8 0.11` / `signature 3.0` / `der 0.8`); `primefield` pinned to rc.9; the sspi/picky forks pinned by rev in the workspace `[patch.crates-io]`. `ml-dsa`'s `from_seed` moved onto `SigningKey`, adapted across `rustion-crypto` + `rustion-control-plane`.
- **Tests:** BV — `build_open_rdp_cert_seals_key_pin_domain_in_extra` (envelope round-trip). Rustion — `SessionCredential::rdp_cert_*` extraction + wrong-kind guard; `SmartCardCredsspParams` field validation, SPN derivation, port/IPv6-bracket stripping. The migration was validated in a clean Linux container (`docker/pqc-migration/`): FIPS 204 ML-DSA-65 sign/verify still round-trips (`cross_impl_ml_dsa` = fips204-sign → ml-dsa-verify, `envelope_roundtrip`), the SSH bastion + flow-control tests stay green, and `--features pkinit` compiles the engine — the full ~620-test Rustion workspace passes.
- **Remaining (live-AD only):** supply the upstream TLS SPKI for the CredSSP `pubKeyAuth` channel binding (the shared live-socket integration step with `rdp-password`), and validate the PKINIT handshake against a real KDC / AD (no such environment available yet — same posture as the pending live-Windows NLA validation).

### Phase 7.3 — Per-tier editor integration + full resolver chain — **Done** (BV 0.7.31)

The four-tier policy is now end-to-end configurable from the GUI and the resolver consults every tier on `session/open`. Phase 7 is fully closed.

- **`RustionPolicyTierEditor`** — single reusable React component that handles all three lower tiers (`type` | `asset-group` | `resource`). Shared shape: transport / bastions / bastion_group / recording dropdowns + lock toggle (hidden on `resource` since per-resource cannot lock) + priority field (visible on `asset-group` only). Component manages its own load/save state via the typed wrappers in `gui/src/lib/rustion.ts`. The Settings panel + the three host pages all drop the same component in.
- **AssetGroupsPage** — embeds `<RustionPolicyTierEditor tier="asset-group" id={info.name} />` in the detail card next to Resources/Secrets. Owner/admin gating happens API-side.
- **ResourcesPage** Connection tab — embeds `<RustionPolicyTierEditor tier="resource" id={info.name} />` next to `ConnectionProfilesPanel`. The component hides the lock toggle (per-resource cannot lock); the API refuses `lock=true` + refuses writes that weaken an upstream lock via probe-resolve.
- **Settings → Rustion → Policy** panel grew a "Resource type policy" subcard. Operator enters a type name (e.g. `ssh-host`, `mysql`) and the same `RustionPolicyTierEditor` loads/edits the per-type policy. No dedicated Resource Types editor exists today; this lets admins manage type policy without that dependency.
- **`session/open` full resolver chain**: the handler now reads three new optional request fields — `resource_id`, `resource_type`, `asset_group_ids` — looks each up in `PolicyStore`, and calls `policy::resolve(global, type, asset_groups, resource)`. The Tauri `RustionSessionOpenRequest` + the TS wrapper grew the matching fields. Existing callers that omit them get global-only resolution (Phase 7.2 behaviour) — backward-compatible.
- The response already carries `policy_transport_source` / `policy_recording_source` / `policy_bastions_source` / `policy_locked_by` (from Phase 7.2) — these are now meaningfully populated from the full chain, so a future "Locked by: <tier>" badge on the connection tab can render off these fields without further server changes.

- **Bastion groups** under `sys/config/rustion/bastion-groups/<name>` — named pools of Rustion targets with per-member priority and a `selection: "ordered" | "random"` flag, gated to admin. CRUD on the API, CLI (`bastionvault rustion bastion-group add | list | rename | members ...`), and Settings → Rustion → Bastion Groups panel.
- **Global policy** at `sys/config/rustion` (`transport_default`, `bastion_group_default`, `recording_default`, `transport_lock`), gated to root.
- **Per-resource-type** `connect.{transport, bastions, bastion_group, recording}` on `ResourceTypeDef` (with its own per-type `transport_lock`), gated to admin.
- **Per-asset-group** `connect.{transport, bastions, bastion_group, recording}` on each [asset group](asset-groups.md) (with `priority` and its own `transport_lock`), gated to admin or the group owner. Multi-membership resolution: most-restrictive `transport`, highest-priority group's `bastions` and `recording`.
- **Per-resource** `connect.{transport, bastions, bastion_group, recording}` override, gated to the resource owner and only writable when no upstream tier is locked.
- **Effective-policy resolver** (`min(global, type, asset-group(s), resource)` for `transport`; nearest-defined-tier for `bastions` / `bastion_group`; strictest of `always > input-redacted > off` for `recording`) used uniformly by the API, the GUI, and the CLI; the Connection tab shows the full resolution chain so the operator sees which tier produced each effective value.
- Settings UI: a new admin-only "Rustion → Global policy" panel; a "Rustion → Bastion Groups" CRUD panel; the existing Resource Types editor gains the per-type fields and lock; the Asset Groups page gains per-group transport + bastion + recording fields with a priority slider; the resource Connection tab gains a read-only badge naming the locking tier when locked upstream.
- Migration path for operators currently on `direct`: a root-only "Force all Connect through Rustion" action that flips `transport_default = rustion-required` + `transport_lock = true` in one step after presenting a diff of every resource that would change behaviour.
- Audit events `rustion.policy.global.update`, `rustion.policy.type.update`, `rustion.policy.asset_group.update`, `rustion.policy.resource.update`, `rustion.bastion_group.update` with full before/after.
- Documentation pass + security-review of the envelope, ticket, replay window, and the policy-lock escalation path (a compromised admin must not be able to *un*-lock a root-locked global; a compromised asset-group owner must not be able to escape a locked type or global).

## Per-side deliverable tables

The two repos are co-developed; each phase below names the files that change on each side. End-to-end demos at the end of every phase require both sides shipped. Rustion's side has its own self-contained spec at [`docs/bastionvault-integration.md`](../../Rustion/docs/bastionvault-integration.md) in the Rustion repo — keep the two in sync.

### Phase 1 — Master cert + Rustion target registry + health monitoring

| Side | Deliverable | Location |
|---|---|---|
| BastionVault | PKI slot for the master signing cert (issue, store, export pub) | `src/modules/rustion/master.rs` |
| BastionVault | `rustion/` mount + `RustionTarget` CRUD (HTTP + CLI) | `src/modules/rustion/{mod,config,http,cli}.rs` |
| BastionVault | Background health pinger (`GET /v1/health` against every target, 30s default, three-strikes-down debounce, status cache) | `src/modules/rustion/health.rs` |
| BastionVault | Settings → Rustion Bastions GUI section (enrolment wizard, per-row health dot) | `gui/src/routes/SettingsPage.tsx` + `gui/src/lib/rustion.ts` |
| BastionVault | Audit events: `rustion.target.enrol`, `rustion.target.health.changed`, `rustion.master.issue` | `src/modules/rustion/audit.rs` |
| BastionVault | CLI: `bastionvault rustion target add|list|test|health`, `bastionvault rustion master export` | `src/modules/rustion/cli.rs` |
| Rustion | New `rustion-control-plane` crate scaffold (empty axum service) | `crates/rustion-control-plane/` |
| Rustion | Authority YAML store + hot reload | `crates/rustion-control-plane/src/authority.rs` |
| Rustion | `GET /v1/health` with master-signed-nonce verification + per-IP rate limit | `crates/rustion-control-plane/src/routes.rs` |
| Rustion | Control-plane identity keypair (load / generate / rotate) | `crates/rustion-control-plane/src/identity.rs` |
| Rustion | TLS listener wired into the server binary, hybrid suite default | `crates/rustion-server/src/main.rs` |
| Rustion | CLI: `rustion authority list|show|enrol`, `rustion control-plane identity export|rotate` | `crates/rustion-server/src/cli.rs` |

### Phase 2 — BVRG-v1 envelope + Rustion control-plane scaffold

| Side | Deliverable | Location |
|---|---|---|
| BastionVault | `bastion-vault-crypto::bvrg::{build, verify}` helpers (hybrid sig + ML-KEM-768 encap + ChaCha20-Poly1305) | `crates/bastion-vault-crypto/src/bvrg.rs` |
| BastionVault | Envelope-builder unit tests against synthetic Rustion keypair | `crates/bastion-vault-crypto/tests/bvrg_roundtrip.rs` |
| Rustion | `envelope.rs` verify + decrypt (mirrors BV side; layout frozen by BV spec) | `crates/rustion-control-plane/src/envelope.rs` |
| Rustion | Replay-protection LRU + skew guard | `crates/rustion-control-plane/src/replay.rs` |
| Rustion | `/v1/sessions` skeleton: parse envelope, return `501 not_implemented` (validates round-trip) | `crates/rustion-control-plane/src/routes.rs` |
| Rustion | `rustion authority test-envelope` — synthetic envelope generator + verifier | `crates/rustion-server/src/cli.rs` |
| Both | Cross-repo integration test: BastionVault builds envelope → Rustion verifies + decrypts | `gui/src-tauri/tests/rustion_envelope.rs` (BV) + corresponding fixture in Rustion |

### Phase 3 — Session open + ticketed SSH proxy + dispatcher

| Side | Deliverable | Location |
|---|---|---|
| BastionVault | Dispatcher: pinned-list or random-from-healthy-pool; skip `down`; advance on 5xx, halt on 4xx | `src/modules/rustion/dispatcher.rs` |
| BastionVault | New connection-profile kind `rustion` with `bastions: string[]` field (empty = global pool) | `gui/src/lib/types.ts` + `gui/src/components/ConnectionProfileEditor.tsx` |
| BastionVault | `rustion_session_open` Tauri command + envelope builder + dispatcher walk | `gui/src-tauri/src/commands/rustion.rs` |
| BastionVault | SSH session window grows `transport: { kind: "rustion", host, port, ticket }` mode | `gui/src-tauri/src/session/ssh.rs` + `gui/src/routes/SessionSshWindow.tsx` |
| BastionVault | Connection-tab dispatcher preview (`Will try: rustion-eu-west-1 → rustion-eu-west-2`) | `gui/src/components/RustionDispatcherPreview.tsx` |
| BastionVault | `session.open` event extended with `transport`, `bastion_id`, `bastion_selection`, `bastion_candidates_tried`, `rustion_session_id` | `src/modules/rustion/audit.rs` |
| Rustion | `session.rs` materialises a session record from a verified envelope | `crates/rustion-control-plane/src/session.rs` |
| Rustion | Ticket vending (single-use, IP-bound, 30s TTL) | `crates/rustion-control-plane/src/session.rs` |
| Rustion | `rustion-ssh` accepts `Rustion ticket: tkt_…` as first auth step, binds socket to session, dials target with decrypted credential | `crates/rustion-ssh/src/ticket_auth.rs` |
| Rustion | Recording starts on first byte (existing recorder, new authority field) | `crates/rustion-recording/src/asciicast.rs` |
| Both | End-to-end demo: BastionVault → Rustion → Linux target through SSH with both pinned-list and random-pool selection | `tests/e2e_rustion_ssh.sh` |

### Phase 4 — RDP through Rustion

| Side | Deliverable | Location |
|---|---|---|
| BastionVault | RDP session window takes `transport: rustion` | `gui/src-tauri/src/session/rdp.rs` + `gui/src/routes/SessionRdpWindow.tsx` |
| BastionVault | ironrdp client connects to bastion TLS+PQC listener instead of the target | `gui/src-tauri/src/session/rdp.rs` |
| Rustion | `rustion-rdp` accepts ticket in `mstshash` cookie position; same auth flow as SSH | `crates/rustion-rdp/src/ticket_auth.rs` |
| Rustion | CredSSP / NLA tested against each credential kind (rdp-password, rdp-cert) | `crates/rustion-rdp/tests/credssp.rs` |

### Phase 5 — Renewal + forced termination

| Side | Deliverable | Location |
|---|---|---|
| BastionVault | `POST /v1/rustion/sessions/{sid}/renew` builds a renewal envelope; GUI auto-renew at `ttl - 60s` with idle skip | `src/modules/rustion/session.rs` + `gui/src/hooks/useSessionRenewal.ts` |
| BastionVault | `DELETE /v1/rustion/sessions/{sid}` (force-terminate); Terminate button on active-sessions panel | `gui/src/routes/SessionsPage.tsx` |
| BastionVault | Master-cert rotation: co-signed envelope to all enrolled bastions | `src/modules/rustion/master.rs` |
| BastionVault | Audit: `session.renew`, `session.terminate`, `rustion.master.rotate` | `src/modules/rustion/audit.rs` |
| Rustion | `POST /v1/sessions/{sid}/renew` validates renewal envelope, extends TTL, enforces `max_renewals` and correlation-id guard | `crates/rustion-control-plane/src/routes.rs` |
| Rustion | `DELETE /v1/sessions/{sid}` tears down the live socket, finalises the recording | `crates/rustion-control-plane/src/routes.rs` + `crates/rustion-control-plane/src/session.rs` |

### Phase 6 — Recording handoff

| Side | Deliverable | Location |
|---|---|---|
| BastionVault | Webhook receiver: verify signature against authority's pinned `recording_webhook_pubkey`, write `recording.linked` audit event | `src/modules/rustion/recording.rs` + `src/modules/rustion/http.rs` |
| BastionVault | 24h fallback poller hitting `GET /v1/sessions/{sid}/recording` on Rustion when the webhook is missed | `src/modules/rustion/recording.rs` |
| BastionVault | "Open recording" link in audit timeline; signed-URL stream from Rustion to player | `gui/src/routes/AuditPage.tsx` |
| BastionVault | In-GUI asciicast playback (existing xterm.js + asciinema-player) and `.rdp-rec` wasm decoder | `gui/src/components/RecordingPlayer.tsx` |
| Rustion | Sidecar JSON on close + signed outbound `recording.ready` webhook (exponential backoff, max 5 retries / ~30 min) | `crates/rustion-control-plane/src/webhook.rs` |
| Rustion | `GET /v1/recordings/{rid}` returns a 60s signed URL, IP-bound to operator | `crates/rustion-control-plane/src/routes.rs` |
| Rustion | `GET /v1/sessions/{sid}/recording` serves the sidecar JSON for the 24h fallback window | `crates/rustion-control-plane/src/routes.rs` |

### Phase 7 — Four-tier transport-and-bastion policy + `rustion-required` mode

This phase is **BastionVault-only**. The transport-and-bastion-policy ladder lives entirely on the vault side; Rustion sees no behavioural change (its authority record's `allowed_targets` still bounds what envelopes the vault can ask for, but the vault is the one deciding *which* Rustion instance to send the envelope to).

| Side | Deliverable | Location |
|---|---|---|
| BastionVault | Bastion-group CRUD (`sys/config/rustion/bastion-groups/<name>`), admin-gated | `src/modules/rustion/bastion_group.rs` |
| BastionVault | Global policy at `sys/config/rustion` (`transport_default`, `bastion_group_default`, `recording_default`, `transport_lock`), root-gated | `src/modules/rustion/policy.rs` |
| BastionVault | Per-resource-type `connect.{transport, bastions, bastion_group, recording}` (+ per-type `transport_lock`), admin-gated | `src/modules/resource/types.rs` |
| BastionVault | Per-asset-group `connect.{transport, bastions, bastion_group, recording}` + `priority` + per-group `transport_lock`, admin- or owner-gated | `src/modules/resource_group/mod.rs` |
| BastionVault | Per-resource `connect.{transport, bastions, bastion_group, recording}` override, owner-gated, read-only when any upstream tier is locked | `src/modules/resource/mod.rs` |
| BastionVault | Effective-policy resolver (`min(...)` for transport, nearest-tier-wins for bastions, strictest-wins for recording) | `src/modules/rustion/policy.rs` |
| BastionVault | Dispatcher integration: resolves the `bastions` value (literal list or group name → expanded list) at session-open time | `src/modules/rustion/dispatcher.rs` |
| BastionVault | Settings → Rustion → Global policy (root-only); Settings → Rustion → Bastion Groups (admin); Resource Types editor fields; Asset Groups page per-group fields with priority slider; resource Connection tab badge naming the locking tier when locked upstream | `gui/src/routes/SettingsPage.tsx` + `gui/src/routes/AssetGroupsPage.tsx` + `gui/src/routes/ResourcesPage.tsx` |
| BastionVault | One-shot "Force all Connect through Rustion" migration action with diff preview, root-only | `gui/src/routes/SettingsPage.tsx` |
| BastionVault | Audit: `rustion.bastion_group.update`, `rustion.policy.global.update`, `rustion.policy.type.update`, `rustion.policy.asset_group.update`, `rustion.policy.resource.update` with before/after + actor | `src/modules/rustion/audit.rs` |
| Rustion | (no changes — Rustion does not know or care which policy tier picked `rustion-required` or which bastion group resolved to itself on the vault side) | — |

### Phase 8.1 — Telemetry pull + Live Sessions page — **Done** (BV 0.7.32 + Rustion 0.7.24)

Lays the cross-fleet observability foundation: a 60s pull loop, authority-scoped read-only telemetry endpoints on Rustion, and a new "Live Sessions" page in the GUI.

- **Rustion `/v1/sessions/active`** — authority-scoped (via `X-Rustion-Authority` header). Returns every active (not-killed, not-expired) session that opened under that authority. Read-only; no envelope required since this is metadata only.
- **Rustion `/v1/sessions/history?since=&limit=`** — paginated rolling history with most-recent-first ordering and a `next_cursor` field. `limit` caps at 1000.
- **Rustion `/v1/stats`** — aggregate metrics per authority: `{active, total, total_duration_secs, top_targets, top_operators}` (top-10 each). Computed on the fly from the in-memory session table; cheap.
- **`SessionStore::snapshot_by_authority` + `stats_for_authority`** new helpers.
- **`require_authority` helper** in `routes.rs` extracts + validates the `X-Rustion-Authority` header for telemetry routes (rejects unknown / revoked authorities with `401`/`403`).
- **BV `src/modules/rustion/telemetry.rs`** new module:
    - `TelemetryCache` — in-memory `HashMap<target_id, TargetSnapshot>` behind a `tokio::sync::RwLock`.
    - `start_poller(core)` — detached 60s `tokio::time::interval` loop spawned at boot from `core.rs` alongside the probe pinger + the 24h recording poller. Mirrors the same lifecycle pattern.
    - Per-target cursor persistence at `rustion/telemetry/<target_id>/cursor` so restarts pick up history from the last pull.
    - Pulls `/v1/sessions/active`, `/v1/sessions/history` (with cursor), `/v1/stats` from every *enabled* enrolled target.
- **BV HTTP routes** `GET rustion/telemetry` (cache snapshot) + `POST rustion/telemetry/poll` (force a synchronous pass + return the fresh snapshot).
- **2 new Tauri commands + TS wrappers**: `rustionTelemetryList`, `rustionTelemetryPoll`.
- **New GUI page `/rustion-sessions`**: cross-bastion Live Sessions view with 5s auto-refresh, search + per-bastion filter, three summary cards (active fleet sessions / lifetime rolling / total session time), one row per active session with operator + src-ip + target + opened/expires/renewals, and a per-row **Terminate** button calling `rustionSessionKill`. Sidebar entry "Live Sessions" added under the existing "Recordings" link.

### Phase 8.2 — Audit witness + rate limiting + replay-log + analytics — **Done** (BV 0.7.33 + Rustion 0.7.25)

Closes the security-and-observability layer of telemetry. Phase 8.3 (separate replay WebviewWindow + `.rdp-rec` WASM decoder + signed-URL replay infrastructure) is the remaining slice.

- **Rustion `/v1/sessions/audit?since=&limit=`** — paginated hash-chain entries read directly from the existing `AuditStore` trait. Wire shape per row: `{sequence, timestamp, actor, session_id, source_addr, event, hash}` where `hash` is lowercase-hex sha256 chain-link. Returns `503 audit_chain_unavailable` if the host didn't wire an `audit_store` into `ControlPlaneState`.
- **Rustion `rate_limit::TokenBucket`** new module — per-(client_ip, authority) token bucket; defaults to 60 token capacity + 4 tokens/sec refill (60s burst). Gates `/v1/sessions/{active,history,audit}` + `/v1/stats` via `require_authority_rate_limited`. Soft GC of stale buckets at the 10k-key cap. 2 unit tests.
- **`client_ip` helper** — reads `X-Forwarded-For` (first hop) or `X-Real-IP` so a reverse proxy can pass the operator's IP through; falls back to `"unknown"`.
- **`ControlPlaneState`** grew `audit_store: Option<Arc<dyn AuditStore>>` and `telemetry_rate_limiter: Option<Arc<TokenBucket>>` fields. Both `None` in tests; production wires them at startup.
- **BV `telemetry::AuditEntry`** new wire-shape struct. The poller pulls `/v1/sessions/audit?since=<last_audit_seq>&limit=500` after the active/history/stats pulls, stamps `target_id` on each row, caps `recent_audit` at 200 in-memory entries, persists every row at `rustion/audit_witness/<target_id>/<hash>`, and emits `rustion.audit.witness` for each as `log::info!` on the BV audit chain. The cursor's `last_audit_seq` advances by Rustion's `next_seq`.
- **`audit::RUSTION_AUDIT_WITNESS = "rustion.audit.witness"`** + **`audit::RECORDING_REPLAYED = "recording.replayed"`** new constants.
- **`POST rustion/recordings/replay-log`** BV route + `rustion_recording_replay_log` Tauri command. The Recordings page now hashes the loaded bytes via `crypto.subtle.digest("SHA-256")`, compares against the sidecar's `sha256`, and reports the result to BV — emitting `recording.replayed` with the operator's identity + `sha256_mismatch` flag. SOC tooling joins on this for "who watched what when".
- **Live Sessions analytics extension**: two new cards aggregate fleet-wide top targets + top operators with horizontal bar visualisations + a "Recent audit witness" table (last 30 entries across all bastions, with event-type badge + hash-prefix column).

### Phase 8.3 — Replay window + WASM frame walker + signed-URL infrastructure — **Done** (BV 0.7.35 + Rustion 0.7.27)

The replay window, the WASM module slot, and the signed-URL plumbing are all in place. The MS-RDPBCGR visual bitmap-update codec is explicitly tracked as a separate engineering project — that's not a Phase 8 deliverable.

- **`SessionReplayWindow`** — new Tauri WebviewWindow route at `/session-replay?recording=<rid>`. Layout-less full-screen player; pulls metadata + bytes from BV (which proxies to Rustion via Phase 6.4 `/v1/recordings/<rid>/blob` or the new Phase 8.3 signed-URL path) and routes to a format-specific renderer (asciicast / rdp-rec / smb-log). Recordings-page modal grew an **Open in window** button next to Download.
- **`rustion_open_replay_window`** Tauri command. Spawns the WebviewWindow at 1200×800 with the recording id in the query string. Re-focuses an existing window for the same recording instead of duplicating.
- **`gui/wasm/rdp-replay/`** new standalone wasm crate (excluded from the BV workspace; built independently with `wasm-pack build --target web`). Exposes `parse_rdp_rec(bytes) → Summary`. Mirrors the TS frame walker: validates the `RREC` magic, parses the JSON header, walks the `(ts:u64 + type:u8 + len:u32 + payload)` event stream, returns event counts split by kind + duration in ms + bytes parsed. 5 native unit tests cover happy path, bad magic, truncated trailers, empty record, short input. The crate makes "wasm shipped in the GUI bundle" real; the visual MS-RDPBCGR bitmap-update codec (RLE + NSCodec + bitmap-cache management) is the separate multi-week engineering track previously called out.
- **Signed-URL recording replay** on Rustion:
  - `POST /v1/recordings/<rid>/replay` — re-uses the same authority + replay gate as `/v1/sessions`. Operator IP comes from the envelope's `operator.src_ip`. Returns `{recording_id, expires_at_unix, ip, signature, stream_url_template, ttl_secs:60}`.
  - `GET /v1/recordings/<rid>?expires=&ip=&sig=` — validates the HMAC-SHA256 tag (over `"/v1/recordings/" || rid || "|" || expires || "|" || ip`, domain-separated), the 60s expiry, and the IP binding (`X-Forwarded-For` / `X-Real-IP` → `client_ip`). Constant-time tag comparison. Serves the bytes with the same `X-Recording-SHA256` / `X-Recording-Format` headers as the authority-gated `/blob` route.
  - `ControlPlaneState.recording_url_signing_secret: Option<Arc<[u8; 32]>>` — `None` returns `503 signed_url_disabled` on both routes. Production wires a per-Rustion 32-byte secret at startup.
  - `hmac` workspace dep added to rustion-control-plane.

### Phase 8.4 — RDP bitmap-update visual codec — **Done** (BV 0.7.36)

In-tree bitmap decoder for `.rdp-rec` recordings; the replay window now shows live canvas playback instead of a text summary.

- **`gui/wasm/rdp-replay/`** decoder grew the full TS_BITMAP_DATA path. `decode_rdp_rec(bytes) → DecodeOutput` exposes per-rectangle `Frame { timestamp_ms, x, y, w, h, bpp, compressed, decoder, rgba, error }` records ready for canvas blitting, plus a `decoder_counts` BTreeMap keyed by `"uncompressed" | "rle16" | "rle24" | "unsupported" | "error"`. Implements:
  - **MS-RDPBCGR § 2.2.9.1.1.3.1.2.2 `TS_BITMAP_DATA`** parsing — single-rectangle per event because `rustion-recording`'s `parse_bitmap_update` strips the outer `numberRectangles` header and emits one rectangle per `EVENT_GRAPHICS` event.
  - **Uncompressed 16/24/32 bpp** with RDP's bottom-up→top-down flip handled by the decoder so the GUI doesn't need to.
  - **RLE16 / RLE24** per MS-RDPEGDI § 3.1.9 — BgRun, FgRun, ColorRun, FOM, SetFgFom, Setfg, Pixels, White/Black runs, plus MegaMega forms.
  - Per-frame error reporting: unsupported codecs surface as `Frame.error` with `decoder: "none"` rather than failing the whole stream — the canvas keeps blitting later frames.
  - 6 new native unit tests (10 total in the crate).
- **`gui/src/lib/rdpDecoder.ts`** — 1:1 TypeScript port of the Rust crate so the GUI can run in-browser without a wasm-pack build step. The Rust crate stays canonical; **6 matching vitest tests** check the TS port doesn't drift.
- **`gui/src/components/RdpReplayCanvas.tsx`** — `<canvas>` sized to the recording's source resolution (header width/height or computed from the rectangle bounding box), animates frames at recording wall-clock timestamps via `requestAnimationFrame`. Controls: Play / Pause / Restart / 1× / 2× / 4× / 8×. A "rendered / skipped / total" counter and a "lossy: NSCodec/RemoteFX/8bpp out of scope" warning badge surface when any frame lands on an unsupported codec path.
- **`SessionReplayWindow`** now routes `rdp-rec` blobs to `RdpReplayCanvas` first; the prior summary view stays reachable behind a "Show details" toggle.

**Out of scope** (recorded here, not as a follow-up phase):

- 8 bpp RLE (vanishingly rare on modern Windows targets).
- NSCodec — separate large codec.
- RemoteFX — separate large codec.
- Bitmap-cache references (cached glyph bitmaps). Frames that hit any of these paths show in the "skipped" counter; the operator can still see the surrounding session and download the raw `.rdp-rec` for an external player.

### Phase 8 — Telemetry pull + in-GUI session replay (original spec table)

| Side | Deliverable | Location |
|---|---|---|
| BastionVault | Telemetry background task: 60s loop polling `/v1/sessions/active`, `/v1/sessions/history`, `/v1/sessions/audit`, `/v1/stats` per healthy target | `src/modules/rustion/telemetry.rs` |
| BastionVault | Cursor persistence (`rustion/telemetry/<target_id>/cursors`) so restarts don't refetch | `src/modules/rustion/telemetry.rs` |
| BastionVault | Signature verification on every `audit` entry before re-witnessing into BV's hash chain as `rustion.audit.witness` | `src/modules/rustion/audit.rs` + `envelope.rs` |
| BastionVault | Live sessions page (admin-only, 5s auto-refresh) + Terminate button | `gui/src/routes/RustionLiveSessionsPage.tsx` |
| BastionVault | Analytics dashboard reading from the persisted aggregate (sessions/hour, top operators, top targets) | `gui/src/routes/RustionAnalyticsPage.tsx` |
| BastionVault | Audit timeline rows for `session.replicated` linking to the recording + the matching `rustion.audit.witness` entry | `gui/src/routes/AuditPage.tsx` |
| BastionVault | Session replay window: separate Tauri WebviewWindow, asciicast via `asciinema-player`, `.rdp-rec` via in-tree WASM decoder | `gui/src/routes/SessionReplayWindow.tsx` + `gui/wasm/rdp-replay/` |
| BastionVault | `rustion_recording_replay` Tauri command + `POST /v1/rustion/recordings/{rid}/replay` HTTP route signing a fresh envelope and returning the per-stream URL | `gui/src-tauri/src/commands/rustion.rs` + `src/modules/rustion/recording.rs` |
| BastionVault | `recording.replayed` audit event on every in-GUI playback (operator id + recording id + sha256 mismatch flag if integrity check fails) | `src/modules/rustion/audit.rs` |
| Rustion | `GET /v1/sessions/active` returns the live sessions scoped to the calling authority | `crates/rustion-control-plane/src/routes.rs` |
| Rustion | `GET /v1/sessions/history?since=&limit=` returns paginated closed-session metadata, authority-scoped | `crates/rustion-control-plane/src/routes.rs` |
| Rustion | `GET /v1/sessions/audit?since=&limit=` returns Rustion's hash-chain entries scoped to the authority, each row carrying the chain's signature so BV can re-verify | `crates/rustion-control-plane/src/routes.rs` |
| Rustion | `GET /v1/stats?bucket=&since=` returns aggregate metrics (sessions/hour, top operators, top targets, durations) per authority | `crates/rustion-control-plane/src/routes.rs` |
| Rustion | `GET /v1/recordings/{rid}` returns a 60s signed URL bound to the operator's IP for the in-GUI player to stream from | `crates/rustion-control-plane/src/routes.rs` |
| Rustion | Rate-limit telemetry endpoints (per IP + per authority) so a runaway puller can't saturate the bastion | `crates/rustion-control-plane/src/rate_limit.rs` |

### Phase 9.1 — Deployment-id + pending-authority holding pen — **Done** (BV 0.7.34 + Rustion 0.7.26)

Lays the trust-establishment foundation: stable BV deployment id, pending-authority holding pen on Rustion, approval workflow, deployment_id binding enforcement.

- **BV `master::get_or_init_deployment_id`** — stable v4 UUID minted on first access and persisted at `sys/rustion/master/deployment-id`. Stamped into every BVRG-v1 envelope's `operator.deployment_id` (via `OperatorContext`) on session-open, renew, and kill paths. Replaces the previous "read from auth.metadata" placeholder which was always empty in practice.
- **BV `GET rustion/deployment-id`** + `rustion_deployment_id_read` Tauri command. The Settings → Rustion → Bastions card now surfaces the deployment id alongside the master pubkey export with a "paste this into the bastion's authority record" note.
- **Rustion `AuthorityStore`** grew two parallel maps: `pending: HashMap<String, PendingAuthority>` and `tombstones: HashMap<String, TombstoneEntry>`. CRUD: `submit_pending` (refuses if already approved or tombstoned), `list_pending`, `get_pending`, `approve_pending(name, max_session_secs, replay_policy) → AuthorityRecord` (deployment_id from the pending record pins onto the new active record), `reject_pending(name, reason)` (drops to tombstones), `list_tombstones`, `is_pending`, `is_tombstoned`. New `PendingAuthority` + `TombstoneEntry` structs.
- **Envelope-verify path** now distinguishes three not-active cases:
  - `403 authority_pending_approval` if the authority has an active enrolment submission.
  - `403 authority_tombstoned` if the name was rejected or deenrolled.
  - `401 unknown_authority` only when none of the above apply.
- **Deployment_id binding check** in the envelope-verify prelude: when the authority record's `deployment_id` is non-empty, envelopes whose `operator.deployment_id` doesn't match are refused with `403 attestation_mismatch`. Empty pinned id = "approved before Phase 9.1 shipped" → accept any (backward-compat); operators upgrade by re-approving.
- **Five new audit constants** on BV: `TARGET_ENROL_SUBMITTED`, `TARGET_ENROL_APPROVED`, `TARGET_DEENROLLED`, `MASTER_ATTEST`, plus the existing `RUSTION_AUDIT_WITNESS` carries the bastion-side authority-lifecycle echoes once the witness puller picks them up.

### Phase 9.2 — Disk-backed pending + approval CLI + deenrol + tombstone CLI + re-attestation timer — **Done** (BV 0.8.0 + Rustion 0.8.0)

> Operator-facing deployment guide:
> [`features/rustion-authority-lifecycle.md`](rustion-authority-lifecycle.md) —
> directory layout, YAML schemas, end-to-end workflow, deployment
> recipes (docker-compose / bare-metal HA / Kubernetes GitOps), audit
> footprint, failure-mode quick reference.


The Phase 9.1 in-memory authority projections now have on-disk YAML mirrors, an operator CLI on the bastion side, and the BV-side attest/deenrol surface (Tauri commands + weekly timer).

**Shipped — Rustion side (0.7.29):**

- **`rustion-control-plane::authority_disk`** new module — `AuthorityYaml` / `PendingYaml` / `TombstoneYaml` DTOs with `schema_version: 1`, base64-encoded ed25519 + ML-DSA-65 pubkey halves, RFC 3339 timestamps. `load_active_dir`, `load_pending_dir`, `load_tombstone_dir`, `save_active`, `save_pending`, `save_tombstone`, `remove_file_for`. Atomic writes via temp-rename. **7 unit tests** covering round-trip, schema-version mismatch, malformed-YAML path reporting, missing-dir-yields-empty, replay-window preservation, and idempotent deletes.
- **`AuthorityStore` grew five disk-backed CRUD methods**: `load_from_disk(active, pending, tombs)`, `submit_pending_on_disk`, `approve_pending_on_disk`, `reject_pending_on_disk`, `deenrol_on_disk`, `untombstone_on_disk`. Each drives both the in-memory map and the YAML file in one shot so a crash mid-flight cannot leave a dangling YAML.
- **`rustion authority` CLI** — five subcommands: `list-pending`, `list`, `list-tombstones`, `approve --name --max-session-secs --replay-window-secs`, `reject --name --reason`, `deenrol --name --reason`, `untombstone --name`. CLI operates directly on the three on-disk directories under `default_config_dir()` (`authorities/`, `authorities-pending/`, `tombstoned/`) and prints a "run `rustion reload` to make the running server pick it up" reminder where the running process needs to reload.
- **End-to-end lifecycle test** `tests/authority_lifecycle.rs` — drives submit → approve → deenrol → resubmit-while-tombstoned (refused) → untombstone, plus rejecting a pending submission, plus the three-projection `load_from_disk` round-trip. **3 integration tests.**
- **`AuthorityPublicKey::MLDSA65_PK_LEN`** made `pub` (was `const`) so the disk DTOs can size the pubkey arrays.

**Shipped — BV side (0.7.38):**

- **`src/modules/rustion/envelope.rs::build_deenrol`** new helper — builds an `op: "deenrol"` envelope with the same operator/correlation/nonce shape as `build_kill`.
- **`src/modules/rustion/enrolment.rs`** new module:
  - `attest_bastion(store, master, operator, bastion_id) -> AttestResult` — single-bastion attest with full HTTP round-trip.
  - `attest_all(store, master, operator) -> AttestAllResult { attempted, succeeded, failed, results: Vec<AttestOutcome::{Ok|Err}> }` — sweep helper; failures don't short-circuit.
  - `deenrol_bastion(target, master, operator, reason) -> DeenrolResult` — tolerant of 404/410 (Rustion already forgot us → success).
  - `RustionStore::list_targets()` helper added in `store.rs` (was only `list_target_ids`).
- **`src/modules/rustion/attest_timer.rs`** new module — `start_attest_timer(core)` spawns a detached tokio interval task ticking every 6 days (safety margin against the ~weekly Rustion-side renew window). Same lifecycle pattern as `probe::start_pinger` / `poller::start_poller`. Wired into `core.rs` boot alongside the existing rustion timers.
- **Two new HTTP routes** in `rustion/mod.rs`:
  - `POST rustion/authority/attest` — `bastion_id` optional (one or all). Emits `rustion.master.attest` per success.
  - `POST rustion/target/deenrol` — sends the signed deenrol envelope. Emits `rustion.target.deenrolled`.
- **Two new Tauri commands** in `gui/src-tauri/src/commands/rustion.rs` + TS wrappers in `gui/src/lib/rustion.ts`: `rustionAuthorityAttest(bastionId?)` and `rustionTargetDeenrol(bastionId, reason?)`.

**Audit emission**: BV-side `rustion.master.attest` and `rustion.target.deenrolled` fire on every success. The Rustion-side `authority.approved` / `authority.rejected` / `authority.tombstoned` / `authority.untombstoned` / `authority.deenrolled` hash-chain entries land when the BV witness puller observes them in the next telemetry tick (Phase 8.2 wired this stream).

**What's out of scope (recorded as separate tracks, not Phase 9.x):**

- **Rustion admin web UI for approval** — the CLI fully covers the operator workflow; a single-page web admin is a Phase 7-style follow-up that doesn't gate v1.
- ~~**`attestation_renew_at` enforcement at envelope-verify time**~~ — **shipped in Phase 9.3** (below).
- **GUI surface for the new Tauri commands** — the commands are callable and tested; surfacing Re-attest / Deenrol buttons on the Bastions Settings card is a small `RustionBastionsTab.tsx` change that can ship incrementally.

### Phase 9.3 — Multi-instance failover completion + `attestation_renew_at` enforcement — **Done**

Two strands land together: the BastionVault-side **multi-instance failover** story (the chosen alternative to Rustion HA) is completed, and the **re-attestation deadline** is enforced end-to-end.

**Multi-instance failover (BastionVault side):**

- **Group `selection: random` is honoured.** `dispatcher::plan_group(members, shuffle, …)` health-filters a group's members in declared order and, when the group's `selection` is `random`, shuffles the survivors. A new `Mode::Group` (audit string `"group"`) distinguishes group-sourced candidate lists from a profile-pinned `ordered-fallback` list and the empty-list `random-pool`. The session-open resolver (`session/open`) threads the resolved group name + selection through `SessionOpenRequest.{bastion_group, bastion_shuffle}`. *(Before this, a group's members were always walked in declared order regardless of `selection`.)*
- **`bastion_group` delete is referentially guarded.** `DELETE /v1/rustion/bastion-groups/{name}` now refuses with `409` while any **locked** policy tier (global / type / asset-group / resource) still pins the group — otherwise a `rustion-required` lock would silently degrade to the random pool. `PolicyStore::locked_group_references(name)` scans every tier; unlocked references are allowed through (they fall back benignly).
- **Dispatcher preview.** `POST /v1/rustion/dispatcher/preview` + the `rustion_dispatcher_preview` Tauri command resolve the effective policy for a resource and run the dispatcher against the live health cache, returning `{mode, group_name, source_tier, candidates:[{id,name,status}], dropped:[{id,name,reason}]}`. The resource **Connection tab** renders this as a live "Will try: A → B" panel (`RustionDispatcherPreview.tsx`) with per-target health dots + a skipped-targets line.
- **Two-instance failover harness.** `tests/e2e/rustion-ssh/` gains `docker-compose.failover.yaml` (adds `rustion-2`) and an opt-in **Step 9** (`E2E_FAILOVER=1`): enrol both bastions, pin an ordered group, open → primary; kill the primary, re-open → secondary; confirm the random pool also excludes the dead primary.

**Re-attestation deadline (Rustion side):**

- **`AuthorityRecord.attestation_renew_at: Option<DateTime<Utc>>`** + the matching `AuthorityYaml` field (round-tripped on disk; absent in v1 YAML → `None` → never enforced, backward-compatible).
- **Set at approval.** `approve_pending` stamps `now + ATTESTATION_WINDOW` (14 days — comfortably longer than BV's 6-day re-attest timer, so one missed sweep doesn't lapse an authority).
- **`POST /v1/authorities/attest`.** The route BV's weekly timer was already calling now exists: it verifies the `op = "attest"` envelope (signature + deployment-id binding + replay), bumps the deadline via `AuthorityStore::attest`, persists the bumped record to the active authorities dir so it survives a hot-reload, emits the `authority.attested` usage event, and returns `{attested_at, expires_at}`.
- **Enforcement at verify.** `verify_and_replay` refuses any envelope from a lapsed authority with `403 attestation_expired` — **except** the `attest` op itself, so a lapsed-but-still-trusted authority can always re-attest its way back to healthy (deadlock-free recovery). A stolen key on a *different* deployment still trips `attestation_mismatch` first, so attest can't be abused to launder a stolen keypair.
- **Tests.** Rustion control-plane integration tests cover the attest round-trip (returns a ~14-day deadline), a lapsed authority's `open` being refused with `attestation_expired`, and a lapsed authority still being able to attest; the disk round-trip test asserts the field survives serialisation. BV dispatcher unit tests cover the ordered-vs-random group paths.

### Phase 9 — Explicit enrolment-approval handshake + re-attestation + tombstones (original spec table)

| Side | Deliverable | Location |
|---|---|---|
| BastionVault | Deployment-id slot: stable UUID minted on first PKI init, included in every BVRG-v1 envelope (`operator.deployment_id`) | `src/modules/rustion/enrolment.rs` + `src/modules/rustion/envelope.rs` |
| BastionVault | Enrolment submit flow: `bvault rustion enrol --target rt_<id>` packages master pubkey + deployment id + requested scope and POSTs the submission envelope | `src/cli/command/rustion_enrol.rs` + `gui/src/components/RustionBastionsTab.tsx` |
| BastionVault | Pending status visible in GUI: target row shows "Awaiting approval" until Rustion flips the authority to active | `gui/src/components/RustionBastionsTab.tsx` |
| BastionVault | Weekly re-attestation timer + `rustion_authority_attest` Tauri command | `src/modules/rustion/master.rs` |
| BastionVault | `rustion_target_deenrol` command sends a `deenrol` envelope before the local registry delete | `src/cli/command/rustion_target_delete.rs` + `gui/src-tauri/src/commands/rustion.rs` |
| BastionVault | Audit: `rustion.master.attest`, `rustion.target.deenrol`, `rustion.authority.*` echoes (reflected from Rustion's witness stream) | `src/modules/rustion/audit.rs` |
| Rustion | `authorities-pending/` holding pen + hot reloader (envelopes signed by pending pubkeys 403 with `authority_pending_approval`) | `crates/rustion-control-plane/src/authority.rs` |
| Rustion | Approval workflow: `rustion authority list-pending`, `rustion authority approve --name`, `rustion authority reject --name` + admin web UI button | `crates/rustion-server/src/cli.rs` + `crates/rustion-server/src/admin/` |
| Rustion | Deployment-id binding: stored at approval time, compared on every envelope; mismatch → `403 attestation_mismatch` | `crates/rustion-control-plane/src/envelope.rs` |
| Rustion | Tombstone directory: deleted authorities live in `tombstoned/<name>.yaml` with frozen deployment id; `rustion authority untombstone <n>` requires explicit admin action | `crates/rustion-control-plane/src/authority.rs` |
| Rustion | Hash-chain entries: `authority.approval_pending`, `authority.approved`, `authority.rejected`, `authority.attested`, `authority.tombstoned`, `authority.untombstoned`, `authority.deenrolled` | `crates/rustion-control-plane/src/authority.rs` |

### Cross-repo testing matrix

| Test | Driver | Verifies |
|---|---|---|
| Envelope round-trip | BV unit test against synthetic Rustion keys | Build / verify / decrypt symmetry |
| Health probe | BV pinger against running Rustion | `GET /v1/health` round-trip + signed-nonce auth |
| SSH session open | E2E script (Docker compose: BV + Rustion + OpenSSH target) | Full Connect flow, recording on |
| RDP session open | Manual against Windows Server VM | CredSSP through bastion |
| Renew + terminate | E2E script | TTL extension, force-disconnect surfaces to operator |
| Dispatcher fallback | E2E with two Rustion instances; kill the primary | Ordered fallback advances; random pool excludes `down` |
| Replay rejection | Integration test sending the same envelope twice | Second attempt → `envelope_replay` |
| Webhook lost | E2E with webhook URL pointing at a black hole | 24h poller eventually links the recording |
| Force-terminate from BV | E2E + audit-log inspection | Session window receives Tauri event; `session.terminate` recorded on both sides |
| Policy escalation | Per-tier lock + non-admin attempts to override | `403 transport_locked` from API + greyed-out GUI |
| Telemetry cursor resume | Restart BV mid-page; confirm next loop continues from the persisted cursor | No history rows lost or duplicated across restart |
| Audit witness verification | Tamper one byte of a returned audit entry's signature | BV's `rustion.audit.witness` write refuses; entry surfaces in a `tampered_audit` red banner |
| Replay URL leak | Capture the signed URL, retry from a different source IP | Rustion refuses with `403 ip_bound` |
| Replay integrity check | Mid-stream byte flip in transit | Player's end-of-stream SHA-256 fails; UI shows "recording integrity check failed" |
| Pending authority refusal | Submit a master pubkey; send an envelope before approval | `403 authority_pending_approval`; BV GUI shows "Awaiting approval" |
| Deployment-id mismatch | Approve enrolment, then re-submit with same pubkey + different deployment id | `403 attestation_mismatch`; chain shows `authority.attestation_mismatch` |
| Tombstone resurrection | Delete an authority, re-submit | Refused with `authority_tombstoned`; only `untombstone` action unblocks |
| Periodic re-attestation lapse | Stop BV's attest timer; let `attestation_renew_at` expire | Next envelope refused with `attestation_expired`; manual `rustion authority refresh-attestation` re-approves |
| Live sessions de-dupe | Two Rustion instances mediate concurrent sessions for the same operator | GUI's Live sessions page shows two rows, not four; session_id uniqueness holds |

## Open questions

- **Two-way mTLS on the control plane? — Resolved: not pursued.** Caller authenticity is already established cryptographically by the BVRG-v1 envelope signature (hybrid Ed25519 + ML-DSA-65) verified against the per-authority pinned pubkey, plus the deployment-id binding and (Phase 9.3) the re-attestation deadline. A client certificate would re-prove the same identity through a second, weaker channel (a TLS PKI) while adding a whole cert lifecycle to operate and rotate. TLS on the control plane stays — but purely for transport confidentiality/integrity, not authentication. (The `serve_tls` listener still *accepts* an optional client-CA bundle for operators who want belt-and-braces, but the integration does not require or rely on it.)
- **Native Rustion auth bypass.** A session opened by BastionVault skips Rustion's own user store entirely — the *authority* is the trust anchor, the *user* is whatever BastionVault attests. Is that the right call for environments that already enrolled their humans in Rustion? Tentative answer: yes, because making humans authenticate twice is the workflow we're trying to remove. Authorities should be policy-scoped (`allowed_targets`, `allowed_actions`) tightly enough that a compromised BastionVault can't reach beyond what it already could.
- **Recording redaction.** `input-redacted` mode is listed in the envelope but Rustion's current recorder either records keystrokes or doesn't. Deciding the policy default per resource type (probably "off" for SSH input, "always" for SSH output) is a Phase 6 sub-question.
- **Rustion HA — Resolved: solved on the BastionVault side, not inside Rustion.** Rather than build an active/passive pair into Rustion, availability on the `rustion-required` path is provided by **multi-instance failover in BastionVault** (see *Multi-instance failover* under Design): operators enrol N Rustion instances, group them, and the dispatcher walks an ordered list (or a healthy random pool), failing over to a sibling bastion when one is `down`/unreachable. A single in-flight *session* is still bound to one instance — if that instance dies mid-session the operator reconnects as a new session on a sibling — but the *service* no longer has a single point of failure. This keeps Rustion itself stateless and simple. Regulated deployments should enrol at least two instances (ideally in distinct failure domains) and pin them via an ordered bastion group.
