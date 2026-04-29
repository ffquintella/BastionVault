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

- [Resource Connect](resource-connect.md) ships seven phases (SSH × {Secret, LDAP, PKI} ✅, RDP × {Secret, LDAP, PKI smartcard via CredSSP} ✅, ⌘K palette, per-type policy). Sessions are direct from the Tauri host; no bastion, no recording.
- BastionVault has a [PKI engine](pki-secret-engine.md) that can issue both classical and ML-DSA / hybrid certs — the master signing cert can ride on existing PKI plumbing (no new key-management subsystem).
- BastionVault has [audit logging](audit-logging.md) (HMAC-chained file device). Pointer events to remote recordings slot into the existing pipeline.
- Rustion (`/Users/felipe/Dev/Rustion`) is its own server with its own user / target / role YAML store, its own auth (password + Argon2id, certificate, SAML, FIDO2, TOTP), and its own admin TUI. It does **not** today expose a control-plane API for "create me a session for this credential, signed by an external trust anchor." That control plane is the new surface this feature adds — symmetric work in both repos.
- There is no integration today; the two products are co-developed by the same author but ship independently.

## Scope

### In scope (BastionVault side)

- **Master Operator certificate** — a long-lived (default 5y) signing cert held in a new `rustion/master` slot under the PKI engine. Hybrid by default (Ed25519 + ML-DSA-65). Public half exported for one-shot enrolment in Rustion.
- **Rustion target registry** — a new top-level `rustion/` mount: each entry stores `id`, `name`, `endpoint` (host:port for the control plane), `public_key` (Rustion's hybrid pubkey, pinned), `default_recording_dir` pointer, `enabled`, `tags`, `health` (see below). **Multi-instance by design** — a deployment registers as many Rustion instances as it has bastions (per-region, per-environment, DR pair, …) and BastionVault treats them as a pool.
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
- **Audit events** — `rustion.target.enrol`, `rustion.target.rotate`, `rustion.target.health.changed`, `rustion.master.rotate`, `session.open` (extended with `transport: "rustion" | "direct"`, `bastion_id`, `bastion_selection: "pinned" | "ordered-fallback" | "random-pool"`, `bastion_candidates_tried`, `rustion_session_id`), `session.renew`, `session.terminate`, `recording.linked`.
- **Three-tier transport policy** — a new `connect.transport` field with the same value space (`direct | rustion | rustion-required`) applied at three levels, evaluated **most-restrictive-wins**:
  1. **Global default** — a deployment-wide setting in `sys/config/rustion` (`transport_default` + `transport_lock`). When `transport_lock = true`, the global value pins every resource and per-type / per-resource overrides are ignored. This is how an admin says *"all Connect, everywhere, must go through a bastion."*
  2. **Per-resource-type** — `connect.transport` on `ResourceTypeDef`, overrides the global default for resources of that type *only if `transport_lock = false`*.
  3. **Per-resource** — `connect.transport` on the individual resource record, overrides the type-level value *only if neither global nor type-level is locked* (a per-type `transport_lock` is also available so a vault admin can pin all `server` resources to Rustion while leaving other resource types free).
  
  The effective transport for a Connect attempt is `min(global, type, resource)` under the ordering `direct < rustion < rustion-required`. A resource owner who sets `direct` on their resource still goes through Rustion if the type or global pins `rustion`. Operators see the effective value and the level it came from in the Connection tab.
- **Admin / root-only configuration** — writing the global `sys/config/rustion` policy and any `transport_lock` flag requires the built-in **`root`** policy or a policy that grants `update` on `sys/config/rustion`. Per-resource-type policy lives on `ResourceTypeDef` and requires the **`admin`** capability on `sys/config/resource-types/*` (same gate as the existing per-type Connect-enabled toggle from Resource Connect Phase 7). Per-resource policy is editable by the resource owner *only when the upstream tiers permit it* — a locked global / type makes the field read-only in the GUI and rejected with `403 transport_locked` from the API. Every change emits a dedicated audit event (`rustion.policy.global.update`, `rustion.policy.type.update`, `rustion.policy.resource.update`) carrying actor, before/after values, and the lock state.
- **GUI: Settings → Rustion bastions** — CRUD for Rustion targets, one-shot enrolment wizard (paste Rustion's pubkey, export master pubkey to clipboard / file), liveness ping, connection-test button. **Settings → Rustion → Global policy** is a separate panel, visible only to root, exposing `transport_default` and `transport_lock`. Resource-type policy lives in the existing Settings → Resource Types editor (admin-only). Per-resource policy is on the resource's Connection tab, disabled with an explanatory tooltip when an upstream tier has locked it.
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
      /** Ordered preference list. Empty/unset = pick at random from the global pool
       *  of healthy enabled targets. Tried in order until one accepts. */
      bastions: string[];
      credential_source: ...;
      recording?: "always" | "off" | "input-redacted"; };
```

The credential-source resolver is unchanged (Secret / LDAP / SSH-engine / PKI). The only difference is what happens *after* resolution: a `direct` profile hands the credential to the local SSH/RDP dialler, a `rustion` profile hands the credential to the envelope builder.

### Tauri command surface (additions)

- `rustion_target_list() -> Vec<RustionTarget>`
- `rustion_target_upsert(target: RustionTargetInput) -> RustionTarget`
- `rustion_target_test(id: String) -> { latency_ms, version, fingerprint }`
- `rustion_target_health(id: Option<String>) -> Vec<{ id, status, last_ok_at, latency_ms_p50, consecutive_failures }>` (omit id = all targets)
- `rustion_dispatcher_preview(resource_id, profile_id) -> { mode: "pinned" | "ordered-fallback" | "random-pool", candidates: [{ id, name, status }] }`
- `rustion_master_pubkey_export() -> { pem, fingerprint, algs }`
- `rustion_session_open(resource_id, profile_id) -> { sid, host, port, ticket, expires_at }`
- `rustion_session_renew(sid: String) -> { new_expires_at }`
- `rustion_session_terminate(sid: String) -> ()`
- `rustion_recording_url(sid: String) -> { url, expires_at }`

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
| `GET` | `/v1/rustion/master/pubkey` | Export master pub (one-shot enrol step) |
| `POST` | `/v1/rustion/master/rotate` | Rotate master cert (co-signed envelope to all enrolled bastions) |
| `POST` | `/v1/rustion/sessions` | Open a new session (consumed by GUI / CLI) |
| `POST` | `/v1/rustion/sessions/{sid}/renew` | Renew |
| `DELETE` | `/v1/rustion/sessions/{sid}` | Force-terminate |
| `GET` | `/v1/rustion/sessions` | List active sessions (BastionVault's own view) |
| `GET` | `/v1/rustion/sessions/{sid}/recording` | Resolve a streaming URL for the recording |
| `GET` | `/v1/rustion/policy` | Read effective global + per-type policy (any authenticated operator) |
| `PUT` | `/v1/rustion/policy` | Update global `transport_default` / `transport_lock` (**root only**) |
| `GET` | `/v1/rustion/policy/effective?resource={id}` | Resolve the effective transport for a specific resource, returning the level the value came from |

All endpoints are policy-gated on `rustion/*` paths in the existing ACL grammar.

### Module / file layout (BastionVault)

```
src/modules/rustion/
  mod.rs                      // mount point, route registration
  config.rs                   // RustionTarget, RustionMaster
  envelope.rs                 // BVRG-v1 build / verify
  client.rs                   // HTTP/2 client to Rustion control plane
  health.rs                   // background pinger + status cache + state-change events
  dispatcher.rs               // bastion selection: ordered-fallback or random-pool
  master.rs                   // master cert lifecycle (issue, rotate, export)
  session.rs                  // session open / renew / terminate state machine
  recording.rs                // recording-pointer storage + signed-URL fetch
  audit.rs                    // event taxonomy
  http.rs                     // axum routes
  cli.rs                      // `bastionvault rustion ...`
gui/src/lib/rustion.ts        // typed Tauri command wrappers
gui/src/routes/SettingsPage.tsx  // + Rustion Bastions section
gui/src/routes/ResourcesPage.tsx // + transport selector on connection profiles
gui/src/routes/AuditPage.tsx     // + recording link rendering
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

### Phase 1 — Master cert + Rustion target registry + health monitoring — **Todo**

- PKI slot for the master cert (issue, store, export pub).
- `rustion/` mount + `RustionTarget` CRUD on the API and GUI, supporting **multiple enrolled instances**.
- Settings → Rustion Bastions section with one-shot enrolment wizard and a per-row health dot.
- Rustion `GET /v1/health` endpoint + BastionVault background pinger (configurable interval, default 30s) with status cache, three-strikes-down / one-success-up debouncing, and `rustion.target.health.changed` audit events.
- CLI: `bastionvault rustion target add|list|test|health`, `bastionvault rustion master export`.
- Audit: `rustion.target.enrol`, `rustion.target.health.changed`, `rustion.master.issue`.
- No session traffic yet; this phase is plumbing + a green/red status indicator the dispatcher will key off in Phase 3.

### Phase 2 — BVRG-v1 envelope + Rustion control-plane scaffold — **Todo**

- `bastion-vault-crypto` gains the `bvrg::{build, verify}` helpers.
- New `rustion-control-plane` crate in `/Users/felipe/Dev/Rustion`. Authority YAML store + hot reload + `/v1/sessions` skeleton that verifies envelopes and returns canned `not_implemented`.
- Round-trip test from BastionVault → Rustion that a syntactically-correct envelope verifies and decrypts; no real session opens yet.

### Phase 3 — Session open + ticketed SSH proxy + dispatcher — **Todo**

- Rustion `/v1/sessions` materialises a session, mints a ticket, returns connection coordinates.
- Rustion SSH listener accepts `ticket@<sid>` as the first auth step and proxies to the target with the decrypted credential.
- BastionVault's SSH session window takes `transport: rustion` and dials the bastion.
- **Dispatcher** (`src/modules/rustion/dispatcher.rs`): given a resource + profile, returns the candidate list — pinned ordered list from the profile, or a uniform random shuffle of all healthy enabled targets when the list is empty. Skips targets where `health.status != "up"`. Walks the list on transport / 5xx failures, surfaces per-target errors, and stops on auth failures (4xx).
- GUI Connection tab shows a live "Will try: …" preview that updates as health changes.
- `session.open` + `session.close` events on both sides include `bastion_selection` + `bastion_candidates_tried`; recording on but pointer not yet fetched.
- End-to-end: Linux target reachable through Rustion with multiple instances enrolled — random selection works in the empty-list case, ordered fallback works when one instance is down.

### Phase 4 — RDP through Rustion — **Todo**

- Rustion RDP gateway accepts the same ticket protocol.
- BastionVault's RDP session window takes `transport: rustion`.
- ironrdp client connects to the bastion's TLS+PQC listener instead of the target; the target side is Rustion's existing RDP proxy.
- CredSSP / NLA tested with Secret, LDAP, and PKI credential sources.

### Phase 5 — Renewal + forced termination — **Todo**

- `POST /v1/sessions/{sid}/renew` and `DELETE /v1/sessions/{sid}` on Rustion.
- GUI auto-renew at `ttl - 60s` with idle skip.
- "Terminate" button on the active-sessions panel.
- Audit: `session.renew`, `session.terminate`.
- Master-cert rotation: co-signed envelope, accepted by enrolled Rustions until the old key's `not_after`.

### Phase 6 — Recording handoff — **Todo**

- Sidecar JSON + outbound signed `recording.ready` webhook from Rustion.
- BastionVault webhook receiver + 24h fallback poller.
- "Open recording" link in audit timeline; signed-URL stream from Rustion to the player.
- asciicast playback in-GUI (existing xterm.js + asciinema-player), `.rdp-rec` playback handed off to a small wasm decoder shipped in the GUI bundle.

### Phase 7 — Three-tier transport policy + `rustion-required` mode — **Todo**

- **Global policy** at `sys/config/rustion` (`transport_default`, `transport_lock`), gated to root.
- **Per-resource-type** `connect.transport` on `ResourceTypeDef` (with its own per-type `transport_lock`), gated to admin.
- **Per-resource** `connect.transport` override, gated to the resource owner and only writable when no upstream tier is locked.
- **Effective-policy resolver** (`min(global, type, resource)` under `direct < rustion < rustion-required`) used uniformly by the API, the GUI, and the CLI; the Connection tab shows both the effective value and the source tier.
- Settings UI: a new admin-only "Rustion → Global policy" panel; the existing Resource Types editor gains the per-type field and lock; the resource Connection tab gains a read-only badge when locked upstream.
- Migration path for operators currently on `direct`: a root-only "Force all Connect through Rustion" action that flips `transport_default = rustion-required` + `transport_lock = true` in one step after presenting a diff of every resource that would change behaviour.
- Audit events `rustion.policy.global.update`, `rustion.policy.type.update`, `rustion.policy.resource.update` with full before/after.
- Documentation pass + security-review of the envelope, ticket, replay window, and the policy-lock escalation path (a compromised admin must not be able to *un*-lock a root-locked global).

## Open questions

- **Two-way mTLS on the control plane?** Today the design relies entirely on the envelope signature for auth and uses TLS only for confidentiality / integrity of the transport. Adding mTLS gives belt-and-braces but requires a second cert lifecycle. Probably a Phase 7 follow-up rather than v1.
- **Native Rustion auth bypass.** A session opened by BastionVault skips Rustion's own user store entirely — the *authority* is the trust anchor, the *user* is whatever BastionVault attests. Is that the right call for environments that already enrolled their humans in Rustion? Tentative answer: yes, because making humans authenticate twice is the workflow we're trying to remove. Authorities should be policy-scoped (`allowed_targets`, `allowed_actions`) tightly enough that a compromised BastionVault can't reach beyond what it already could.
- **Recording redaction.** `input-redacted` mode is listed in the envelope but Rustion's current recorder either records keystrokes or doesn't. Deciding the policy default per resource type (probably "off" for SSH input, "always" for SSH output) is a Phase 6 sub-question.
- **Rustion HA.** Rustion isn't itself HA today. If we put it on the critical path for Connect, do we need an active/passive pair before going to `rustion-required`? Probably yes, and that becomes a prerequisite for Phase 7 in regulated deployments.
