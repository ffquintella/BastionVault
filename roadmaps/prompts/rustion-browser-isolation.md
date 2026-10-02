# Prompt: prepare Rustion for BastionVault web browser isolation

Paste the block below into an agent session opened **in the Rustion repository**.
It drives the Rustion-side half of BastionVault's Web Application Connect
Phase 8 ([features/web-application-connect.md](../../features/web-application-connect.md) §12,
roadmap task T97). It asks for a design spec and a roadmap entry first, not
code.

---

```text
You are working in the Rustion repository: a Rust SSH/RDP/SMB bastion with
post-quantum transport and tamper-evident session recording. Read the repo's
agent instructions (AGENTS.md / CLAUDE.md, if present) and follow them.

## Context

BastionVault (a Rust secrets vault with a Tauri desktop GUI) already
integrates with Rustion. Read Rustion's side of that contract before doing
anything else:
  - docs/bastionvault-integration.md (the Rustion-side spec)
  - the control-plane crate (BVRG-v1 envelope verify/decrypt, authority store,
    /v1/sessions, ticket vending, recording sidecar + recording.ready webhook)
  - the RDP proxy and the .rdp-rec recorder

Summary of the existing contract, which you must verify against the code
rather than trust:
  - BastionVault signs (hybrid Ed25519 + ML-DSA-65) and seals (ML-KEM-768 +
    ChaCha20-Poly1305) a CBOR payload called BVRG-v1 with op open|renew|kill,
    target {host, port, protocol, hostkey_pin?}, credential {kind, material,
    username, extra}, session {ttl_secs, max_renewals, recording}, operator
    {...} and correlation_id.
  - Rustion verifies it against an enrolled authority, materialises a session,
    and returns {session_id, host, port, ticket, expires_at}. The operator's
    client connects to Rustion's SSH/RDP listener presenting ticket@session_id.
  - On close, Rustion writes a recording sidecar and sends a signed
    recording.ready webhook. BastionVault replays .rdp-rec recordings in its
    GUI.

## What BastionVault wants to add

BastionVault is adding a "web application" resource type: Connect opens a web
app and logs the operator in by filling a declarative login recipe (username /
password / TOTP into CSS-selected form fields across one or more pages, with
success_when / failure_when conditions), by HTTP auth, or by SSO.

The highest-assurance mode, "rustion-isolated", must run the browser on the
Rustion side, so that the credential never reaches the operator's machine:

  1. BastionVault sends a BVRG-v1 open envelope with target.protocol = "web",
     credential.kind = "web-form" | "web-http-auth" | "web-none", and
     credential.extra = { totp_codes (current + next step; never the seed),
     recipe, recipe_hash, start_url, allowed_origins, tls_pin_sha256,
     allow_downloads, clipboard }.
  2. Rustion verifies the envelope and starts a disposable per-session browser
     worker: Chromium in kiosk mode, fresh empty profile, enterprise policies
     derived from the envelope (URL allow-list, devtools disabled, downloads
     restricted, password manager and extensions off), network egress limited
     to allowed_origins plus DNS.
  3. A worker agent receives the recipe and credential from Rustion over an
     authenticated local channel and performs the login through the Chrome
     DevTools Protocol bound to localhost. It applies these safety checks:
     exact origin match, https only, top frame only, exactly one visible,
     non-occluded input of the expected type, form action resolving to an
     allowed origin. Password fields are cleared after submit. It reports a
     structured outcome (success | failure | timeout | aborted:<check>).
  4. The operator connects with BastionVault's existing RDP client to
     Rustion's RDP listener using ticket@session_id. Rustion proxies to the
     worker's RDP endpoint and records the session as a normal .rdp-rec.
  5. On close, or on any failure, Rustion destroys the worker, with no state
     reused across sessions, and writes the sidecar with the navigation
     origins (origins only, never paths or queries) and the recipe outcome.
     It also records the events in Rustion's hash chain.

## Your task (design and prepare; do not implement yet)

1. Survey the code paths above and write down, with file:line references, how
   envelope kinds, protocols, targets, RDP proxying and recording are wired
   today, and where a "web" protocol and a "browser worker" target would plug
   in.
2. Write a new spec in Rustion's docs/feature-spec location (follow the repo's
   existing format) titled "Browser isolation workers for BastionVault web
   sessions". It must cover:
   - BVRG-v1 additions. They must be additive, keep v:1 payloads readable, and
     reject an unknown credential.kind (fail closed, never ignored). Include
     compatibility tests with old payloads.
   - Worker technology. Compare a per-session Podman container, a microVM
     (Firecracker / Cloud Hypervisor) and a pre-warmed pool. Cover Chromium's
     sandbox requirements inside containers (user namespaces / seccomp),
     start-up latency, density and isolation. Recommend one.
   - The RDP endpoint inside the worker. Compare xrdp in the worker image with
     an embedded ironrdp-server fed by a virtual framebuffer, and assess the
     impact on the existing recorder.
   - The Rustion ↔ worker-agent control channel: authentication, how the
     credential is delivered and zeroized, timeouts, and the outcome
     reporting.
   - Policy enforcement inside the worker: the Chromium enterprise policy set
     (list exact policy names) and the egress filter mechanism.
   - Clipboard and file transfer, reusing the existing RDP channel policies.
   - Lifecycle: spawn, TTL and renew, kill envelope, crash cleanup, orphan
     reaping, per-authority limits, and the health and capacity fields added
     to GET /v1/health.
   - Audit and recording: new hash-chain events, sidecar fields, what is
     never logged (credentials, TOTP codes, cookies, full URLs).
   - Operations: building and signing the worker image, and the Chromium
     security-patch cadence (who rebuilds and within what SLA).
   - A threat model: hostile page content, worker escape, credential exposure
     inside the worker, malicious recipe data, replayed envelopes.
   - Phases, a testing plan (including a fixture login site with hostile
     cases: opacity-0 decoy field, overlay-covered field, cross-origin iframe
     login, off-origin form action, redirect to a non-allowed origin), and
     open questions.
3. Add the feature to Rustion's roadmap / tracking files in the repo's format,
   as planned (not started), and reference BastionVault's spec
   features/web-application-connect.md §12 and task T97.
4. List any changes the BastionVault side would need beyond what is described
   above. Do not edit the BastionVault repo.

Constraints:
  - Do not write production code in this task.
  - Do not weaken any existing envelope verification, authority check or
    ticket rule.
  - Keep the recipe format a shared, versioned contract. Propose where its
    canonical schema should live so both repos validate the same thing.
  - State assumptions and call out security trade-offs explicitly.
```
