# Feature: Machine Authentication (FerroGate)

## Summary

A new auth method that lets BastionVault **only admit known, authorized machines** by delegating the
*"is this a real, attested machine?"* question to **[FerroGate](../../FerroGate)** — a TPM 2.0-attested,
post-quantum SPIFFE machine-identity system — and keeping for itself the *"is this machine **allowed** to use
**this** vault?"* question via an **administrator approval gate**.

FerroGate already proves a machine's identity in hardware: its Machine Identity Agent (MIA) runs a four-phase
TPM attestation handshake against the Central Machine Identity Service (CMIS) and obtains a short-lived,
composite-signed (Ed25519 **and** ML-DSA-65) **SVID** bound to the host's TPM Endorsement Key. The MIA can then
mint short-lived, **DPoP-bound child tokens** for a named audience. BastionVault becomes the *relying party*: a
client on an attested host asks its local MIA for a child token whose audience is the BastionVault server,
presents it, and BastionVault **cryptographically verifies it offline** against FerroGate's published
verification keys (JWKS + CRL).

A valid FerroGate token proves the machine is genuine and hardware-attested — but **not** that it may use this
vault. So the first time a new machine (identified by its stable SPIFFE ID) presents a valid token, BastionVault
records a **pending enrolment** and denies real access (`403 enrolment_pending`) until an **administrator
approves it** from the GUI (*Auth → Machines*) or the CLI (`bvault ferrogate approve <spiffe-id>`). On approval
the admin attaches the policy set the machine may use; subsequent logins mint a normal BastionVault token bound
to those policies.

To break the bootstrap chicken-and-egg (you need an approved machine to do admin work, but approval needs an
admin), **the first machine that authenticates while the system holds zero approved machines and presents a
valid BastionVault root token is auto-approved** with a configurable bootstrap policy. Every later machine goes
through the human-in-the-loop gate.

This is implemented as a **self-contained plugin** (an in-tree auth module mounted at `auth/ferrogate/`, built
as its own crate so it stays cleanly separable) that depends only on FerroGate's published, `#![forbid(unsafe_code)]`
**reference verifier crates** — no custom crypto.

> **Supersedes the earlier host-fingerprint design.** A prior draft of this feature had BastionVault roll *its
> own* machine identity from a host-hardware fingerprint (CPU/SMBIOS/disk/NIC) plus a locally-stored random part,
> with an optional TPM backend. That approach is **dropped** in favour of delegating hardware-rooted identity to
> FerroGate: the fingerprint was only software-readable (no in-silicon signing key), whereas a FerroGate SVID is
> bound to a TPM-resident key that never leaves the chip and is verified through a vendor-rooted EK chain. The
> admin-approval workflow, audit-event vocabulary, and *Auth → Machines* GUI shape carry over unchanged; only the
> identity-proof half is replaced.

## Security model — what this does and doesn't protect

**Protects against**

- **Unattested / unknown machines.** A machine with no FerroGate MIA, or one FerroGate has not enrolled
  (its TPM EK hash is not in the CMIS fleet manifest), cannot obtain a child token at all → it can never reach
  even the `pending` state.
- **Stolen bearer token replay.** Child tokens are DPoP sender-constrained: a captured token presented without
  the matching DPoP private-key proof is rejected (`verify_bound` fails). Tokens are also short-lived (≤ 600 s).
- **Quantum (harvest-now-decrypt-later) forgery.** The token signature is composite — an attacker must break
  **both** Ed25519 and ML-DSA-65 to forge it.
- **Revoked / decommissioned hosts.** FerroGate publishes a composite-signed CRL inside the JWKS extension;
  BastionVault refuses tokens whose SVID/`jti` is revoked.
- **Unauthorized-but-genuine machines.** A real attested machine still cannot use the vault until an admin
  approves its SPIFFE ID. Genuine ≠ authorized.

**Does NOT protect against**

- **A FerroGate compromise.** BastionVault trusts FerroGate's signing key as the machine-identity root. If CMIS's
  composite key is compromised an attacker can mint valid tokens. Mitigation is FerroGate's own (TEE-resident,
  Shamir 3-of-5 key); BastionVault's residual defense is the admin-approval gate — a freshly forged SPIFFE ID is
  still `pending` until approved.
- **Local privileged compromise on an approved host.** `root` on an already-approved, attested host can ask the
  local MIA for child tokens (subject to FerroGate's own caller allowlist). Mitigation: short BastionVault token
  TTLs, admin revoke, audit alerting on unexpected source IPs.
- **Misconfigured trust anchor.** If the operator points `auth/ferrogate/config` at the wrong JWKS / trust domain,
  the gate is only as good as that config. Config writes are root/sudo-gated and audited.

## Motivation

- **Hardware-rooted, non-exportable machine identity.** A FerroGate SVID is bound to a TPM-resident key that
  never leaves the chip — the strongest machine-trust posture BastionVault can offer, and strictly better than a
  software-readable host fingerprint.
- **Don't reinvent attestation.** FerroGate already does TPM quote verification, RIM allowlists, credential
  activation, fleet enrolment, CRLs, and formal proofs. BastionVault should *consume* that, not duplicate it.
- **Two-party authorization the operator understands.** The machine proves *what it is* (FerroGate); the admin
  decides *what it may do* (BastionVault policies). Clean separation of attestation from authorization.
- **Reuse vetted, self-contained verifiers.** FerroGate ships `ferro-svid-verify` and `ferro-child-verify` as
  copy-pasteable, `#![forbid(unsafe_code)]` reference verifiers whose only crypto dependency is `ferro-crypto`'s
  composite primitive — exactly the "use vetted libraries, avoid custom crypto" posture `agent.md` mandates.
- **No human-in-the-loop today for new machine trust.** Today a new client is trusted because someone handed it
  a working `secret_id`. This feature adds an explicit admin-approval gate keyed on a hardware-attested identity.

## Current State

- Not started. This document is the design projection.
- BastionVault ships Token, UserPass, AppRole, Certificate, and FIDO2/WebAuthn auth methods. None consume an
  external attestation authority.
- FerroGate (sibling repo `../FerroGate`) exposes: a CMIS `JWKS` gRPC RPC returning composite verification keys
  plus the signed CRL (`x-ferrogate-crl` extension); SVIDs of `typ: ferrogate-svid+jwt`; child tokens of
  `typ: ferrogate-child+jwt`; and the two reference-verifier crates with public entry points
  `ferro_svid_verify::verify` / `verify_unrevoked` and `ferro_child_verify::verify` / `verify_bound`.

## Identity model — how a machine proves itself

The authoritative machine identity is the **SPIFFE ID** FerroGate derives from `SHA-384(ek_cert)`:

```
spiffe://ferrogate.<env>/host/<uuid>
```

It appears as `iss` on the host SVID and as `iss` on every child token that host mints. BastionVault keys all
enrolment records on this SPIFFE ID — it is stable across SVID rotations and across child tokens.

### Verification path (recommended: child-token + DPoP)

The FerroGate-intended path for a host application talking to a third-party API. The BastionVault client is that
application:

```
client host (FerroGate MIA present)                         BastionVault server
  1. client → local MIA helper socket:
       HelperReq { audience: "<bvault-url>", dpop_jkt, ttl_secs ≤ 600 }
     MIA returns a child token (ferrogate-child+jwt), DPoP-bound to the client's key
  2. client builds a DPoP proof JWS over (htm=POST, htu=<login url>, iat, jti)
  3. POST auth/ferrogate/login
       headers: DPoP: <proof-jws>
       body:    { token: "<child-token>" }                  ──►
                                                              verify_bound(
                                                                token, jwks, Some(dpop_proof),
                                                                DpopExpectation{htm,htu,...}, now, leeway)
                                                              → Verified { claims }   (or fail-closed)
                                                              extract spiffe_id = claims.iss
                                                              look up enrolment(spiffe_id)
                                                              ├─ approved  → mint BastionVault token (policies)
                                                              ├─ pending   → 403 enrolment_pending
                                                              ├─ none      → create pending; 403 enrolment_pending
                                                              │              (unless bootstrap auto-approve, below)
                                                              └─ rejected/revoked → 403
                                              ◄── { client_token, lease_duration, accessor } | 403
```

`verify_bound` (from `ferro-child-verify`) checks, fail-closed: three well-formed segments; the FerroGate child
`alg`/`typ`; a `kid` present in the configured JWK set; a valid **composite** (Ed25519 **and** ML-DSA-65)
signature; the `exp` bound; **and** the DPoP sender-constraint (the proof's RFC 7638 thumbprint equals the
token's `cnf.jkt`, and the proof matches this HTTP request). Revocation is enforced by checking the JWKS's
`x-ferrogate-crl` extension.

### Alternative path (direct SVID)

For hosts/clients that present the host SVID itself rather than a minted child token (e.g. a thin agent without
the MIA helper round-trip), BastionVault verifies with `ferro_svid_verify::verify_unrevoked`. This drops the
per-request DPoP sender-constraint, so it is **opt-in** via `auth/ferrogate/config { accept_svid: true }` and
documented as the weaker mode. Default is child-token-only.

### Trust anchor (JWKS) distribution

`auth/ferrogate/config` records how BastionVault obtains FerroGate's composite verification keys + CRL. Two
sources, pick one:

1. **`cmis_grpc`** *(recommended)* — BastionVault periodically calls the CMIS `JWKS` RPC over hybrid-PQC TLS,
   pinning CMIS SPKI hashes from config; caches keys + CRL; refreshes on a configurable interval (default 60 s,
   matching FerroGate's CRL cadence). Stale-while-revalidate with a hard max-age fail-closed.
2. **`static_jwks`** *(air-gapped / simple)* — operator pastes a pinned JWK set; CRL refresh is the operator's
   responsibility (documented caveat). Useful for tests and offline deployments.

Config fields: `trust_domain` (e.g. `ferrogate.prod`), `expected_audience` (this vault's URL, matched against
child-token `aud`), `jwks_source`, CMIS endpoint + SPKI pins (for `cmis_grpc`), `jwks` blob (for `static_jwks`),
`accept_svid` (default `false`), `clock_leeway_secs` (default 60), `default_token_ttl`, and the bootstrap knobs
below. Writes are root/sudo-gated and audited; secrets (none here — all public keys) are not logged.

## Bootstrap: first-machine auto-approval

Goal: *"the first machine to login using the root token should be automatically authorized."*

Rule, evaluated at `auth/ferrogate/login` when an unknown SPIFFE ID presents a fully-verified FerroGate token:

```
if config.bootstrap_root_auto_approve
   and approved_machine_count == 0
   and request carries a valid BastionVault token with the "root" policy:
       auto-approve this SPIFFE ID with config.bootstrap_policies (default: ["default"])
       emit ferrogate.machine.bootstrap_approved (records actor = root, spiffe_id)
       mint token immediately
else:
       create/keep pending; 403 enrolment_pending
```

Properties:

- **One-shot by construction:** the condition `approved_machine_count == 0` is only ever true once; the moment
  the first machine is approved, every later machine takes the normal admin-approval path.
- **Requires root, not just any token:** the bootstrap login must be authenticated by the BastionVault root
  token (or a `sudo`/root-policy token), so an attacker who merely owns an attested host cannot self-bootstrap.
- **Disable-able:** `bootstrap_root_auto_approve: false` forces *every* machine — including the first — through
  explicit admin approval, for operators who want zero auto-grants.
- **Embedded mode:** in the Tauri embedded vault the operator *is* root locally, so the first machine bootstrap
  is the natural path; documented.

## Scope

### In scope — server (the `ferrogate` auth plugin)

- **New auth backend** mounted at `auth/ferrogate/` (configurable mount path). Routes (all under the `v2/`
  HTTP prefix per `agent.md`):
  - `POST auth/ferrogate/config` / `GET auth/ferrogate/config` — root/sudo-gated trust-anchor configuration
    (fields above). `GET` redacts nothing sensitive (all public) but is still admin-gated.
  - `POST auth/ferrogate/login` — unauthenticated path (no prior BastionVault token required, except that the
    bootstrap branch *reads* a presented root token if any). Body `{ token }`, header `DPoP: <proof>`. Verifies,
    resolves enrolment state, mints a token or returns `403 enrolment_pending` / `403 enrolment_rejected` /
    `403 machine_revoked`. On an unknown SPIFFE ID it **creates** the pending record as a side effect so it
    surfaces in the admin queue.
  - `GET auth/ferrogate/enrolment/{spiffe_id}` — status poll. Returns `{ status, approved_at, approver,
    policies, ttl_seconds }`. Readable by a presenter of a valid (even if `pending`) FerroGate token for that
    SPIFFE ID, so a client can poll its own status without admin rights.
  - `LIST auth/ferrogate/machines` — admin-only; lists machines with `spiffe_id`, short id, status, first-seen,
    last-login, last source IP, attestation summary (`ek_cert_sha384` prefix, `policy_id`), attached policies.
  - `POST auth/ferrogate/machines/{spiffe_id}/approve` — admin approves; body `{ policies, ttl_seconds,
    max_uses?, comment? }`. Approver cannot grant policies they don't hold (same rule as other policy-granting
    paths; `sudo` is the escape hatch). Audited.
  - `POST auth/ferrogate/machines/{spiffe_id}/reject` — admin rejects with `{ reason }`. Audited.
  - `POST auth/ferrogate/machines/{spiffe_id}/revoke` — admin revokes an approved machine; active
    BastionVault tokens for it are revoked through the lease manager. Audited.

- **Storage layout** under the backend's barrier-encrypted view:
  - `config` — the trust-anchor config blob.
  - `machine/<spiffe_id_hash>` — `{ spiffe_id, status, policies, ttl_seconds, ek_cert_sha384, policy_id,
    first_seen_at, approved_at, approver, last_login_at, last_login_ip, reject_reason? }`. Keyed by a salted
    hash of the SPIFFE ID to avoid storing raw ids as keys.
  - `jwks_cache` — last-fetched JWK set + CRL + fetch timestamp (for `cmis_grpc` source).
  - `index/approved_count` — small counter to make the bootstrap check O(1).
  - All entries encrypted under the existing barrier; no new crypto introduced.

- **Verification core** — a thin wrapper around `ferro-child-verify` / `ferro-svid-verify`. The plugin crate
  depends on `ferro-child-verify`, `ferro-svid-verify`, and `ferro-crypto` (path/git dependency on the sibling
  repo, version-pinned). No signature/crypto code is written in BastionVault — only orchestration.

- **JWKS refresher** — for `cmis_grpc`, a background task (lifecycle-tied to the mount) that refreshes the
  cached JWKS + CRL on `jwks_refresh_secs`, with stale-while-revalidate and a hard fail-closed max-age.

- **Audit events** — `ferrogate.config.write`, `ferrogate.machine.first_seen`, `ferrogate.machine.bootstrap_approved`,
  `ferrogate.machine.approved`, `ferrogate.machine.rejected`, `ferrogate.machine.login`,
  `ferrogate.machine.login.denied` (with reason: `pending` | `rejected` | `revoked` | `verify_failed`),
  `ferrogate.machine.revoke`, `ferrogate.token.renew`. Each carries `spiffe_id`, attestation summary, source IP,
  and (for admin actions) actor + comment. **Never** logs token bytes or DPoP proofs.

- **Rate limits** — `login` is per-source-IP rate-limited (default 10/min, configurable) so a flood of unknown
  SPIFFE IDs can't spam the pending queue.

- **Policy integration** — the minted token carries exactly the policies from the approval payload (or
  `bootstrap_policies` for the auto-approved first machine), renewable like any other Vault token.

### In scope — client (`bvault` CLI)

- **`bvault ferrogate login --server <url>`** — the command a service/cron runs each time it needs a token:
  1. Connects to the local FerroGate MIA helper socket, requests a child token for `audience = <server>`.
  2. Builds a DPoP proof for the login request.
  3. `POST auth/ferrogate/login`; on `200` writes the BastionVault token to
     `~/.config/bvault/<server-name>/token` (or stdout); on `403 enrolment_pending` exits non-zero with a
     clear "awaiting admin approval" message.
- **`bvault ferrogate status --server <url>`** — fetches and prints the machine's enrolment status, SPIFFE ID,
  attestation summary, and approved policies.
- **`bvault ferrogate whoami`** — prints the local SPIFFE ID (read from the MIA / current SVID) so an operator
  can copy it into an `approve` command.
- The client **requires a running FerroGate MIA**; if the helper socket is absent it fails with a clear
  `ferrogate_mia_unavailable` hint rather than falling back to anything weaker.

### In scope — admin tooling

- **CLI** — `bvault ferrogate list`, `bvault ferrogate approve <spiffe-id> --policy default --ttl 720h
  [--comment ...]`, `bvault ferrogate reject <spiffe-id> --reason ...`, `bvault ferrogate revoke <spiffe-id>`,
  `bvault ferrogate show <spiffe-id>`, `bvault ferrogate config ...`. Admin-gated identically to the GUI.
- **Admin GUI page** — `Settings → Auth → Machines`, reusing existing admin-page chrome (pagination, search,
  audit-style timeline) — no new components:
  - **Pending** — rows: short SPIFFE id, attestation summary (`ek_cert` prefix + `policy_id`), first-seen age,
    *Approve* / *Reject*. Approve modal requires picking the policy set (filtered to the operator's grant-able
    policies) + TTL + optional comment.
  - **Approved** — searchable; last-login, source IP, current token count, *Revoke*.
  - **History** — rejections, revocations, and bootstrap approvals as an audit-style timeline.
  - **Config** — a small panel to set/inspect the trust anchor (trust domain, audience, JWKS source + CMIS
    endpoint/pins or static JWKS, `accept_svid`, bootstrap knobs). Responsive per the GUI rules (no `max-w-*`
    on the container; `grid grid-cols-2 gap-3` forms; `min-w-0`/`truncate` on SPIFFE IDs and endpoints).
  - Add `{ value: "ferrogate", label: "FerroGate Machine Identity" }` to `MountsPage.tsx`'s `AUTH_TYPES`.

### Out of scope (explicit)

- **Issuing or rotating SVIDs.** That is FerroGate's job. BastionVault only verifies and authorizes.
- **TPM interaction in BastionVault.** All TPM work happens in the FerroGate MIA/CMIS. BastionVault never
  touches `/dev/tpmrm0`.
- **Self-service approval beyond the one-shot root bootstrap.** Every non-bootstrap machine requires an admin.
- **Mutating FerroGate state** (enrol/revoke hosts in FerroGate). Decommissioning a host is done in FerroGate;
  BastionVault honors the resulting CRL and additionally offers its own `revoke` for vault-scoped removal.
- **A FerroGate-less fallback.** This backend assumes a FerroGate fleet. Deployments without FerroGate use
  AppRole / Certificate auth instead; there is no home-grown host-fingerprint fallback (the superseded design).

## Workflow Diagrams

### Enrolment + approval

```
client (attested host)                       server                      admin
  │  bvault ferrogate login                    │                          │
  │   ├─ MIA → child token (aud = server)       │                          │
  │   ├─ build DPoP proof                       │                          │
  │   └─ POST auth/ferrogate/login              │                          │
  │ ───────────────────────────────────────────►│                          │
  │     verify_bound(token, jwks, dpop, …)      │                          │
  │     spiffe_id unknown → create pending      │                          │
  │              403 enrolment_pending          │                          │
  │ ◄───────────────────────────────────────────│   LIST machines          │
  │                                             │ ◄────────────────────────│
  │   (client retries / polls status)           │   approve <spiffe-id>    │
  │ ───────────────────────────────────────────►│ ◄────────────────────────│
  │              403 enrolment_pending          │   policies + ttl + note  │
  │ ◄───────────────────────────────────────────│                          │
  │  bvault ferrogate login (after approval)    │                          │
  │ ───────────────────────────────────────────►│                          │
  │              {client_token, lease, accessor}│                          │
  │ ◄───────────────────────────────────────────│                          │
```

### First-machine bootstrap (root auto-approve)

```
operator on attested host                     server
  │  (holds BastionVault root token)            │   approved_machine_count == 0
  │  bvault ferrogate login                     │
  │   token=<child>  +  X-Vault-Token: <root>   │
  │ ───────────────────────────────────────────►│
  │     verify_bound(...) ok                    │
  │     unknown spiffe_id + root + count==0      │
  │     → auto-approve (bootstrap_policies)      │
  │              {client_token, lease, accessor}│
  │ ◄───────────────────────────────────────────│
  │   (every later machine → normal pending)    │
```

## Phases

| # | Title | Notes |
|---|---|---|
| 1 | **Plugin skeleton + config + storage** | `auth/ferrogate/` mount as a self-contained crate, `config` read/write, storage layout, audit-event scaffolding, admin `list`/`approve`/`reject`/`revoke` against fixture records. `login` stubbed `not_implemented`. |
| 2 | **Verification core (static JWKS) + login** | Wire `ferro-child-verify::verify_bound` end-to-end with a `static_jwks` trust anchor. Child-token + DPoP login mints a token for an *already-approved* fixture machine; unknown → pending. Deterministic tests with fixture tokens/JWKS exported from FerroGate test vectors. |
| 3 | **Enrolment state machine + bootstrap** | First-seen → pending creation as a login side effect, status poll, admin approve/reject/revoke transitions, and the **root-token one-shot bootstrap** (`approved_count == 0` + root). Integration test: unknown machine denied → admin approve → next login succeeds; and the bootstrap happy path. |
| 4 | **CMIS gRPC JWKS source + CRL** | `cmis_grpc` source with SPKI-pinned hybrid-PQC TLS fetch, cache, periodic refresh, CRL enforcement (revoked token rejected). Stale/fail-closed tests. |
| 5 | **Client CLI** | `bvault ferrogate login|status|whoami` driving the MIA helper socket + DPoP proof construction; clear errors when the MIA is absent or the machine is pending. |
| 6 | **Admin GUI page** | `Settings → Auth → Machines` (Pending/Approved/History/Config tabs), `AUTH_TYPES` entry, responsive per GUI rules. UI tests under `vitest`. |
| 7 | **Direct-SVID mode + hardening + docs** | Opt-in `accept_svid` path via `verify_unrevoked`; rate limits on `login`; dashboard metrics (`ferrogate_pending_total`, `ferrogate_approved_total`, `ferrogate_login_total`, `ferrogate_login_denied_total`); threat-model write-up under `docs/`; operator setup guide (FerroGate trust-anchor config, bootstrap recipe, CRL caveats for `static_jwks`). |

## Open questions

- **Child token vs. direct SVID as the default.** Recommended default is child-token + DPoP (sender-constrained,
  short-lived, FerroGate's intended relying-party path). Direct-SVID is weaker (no per-request DPoP) and stays
  opt-in. Confirm no deployment needs SVID-direct as the *default*.
- **How BastionVault depends on the FerroGate verifier crates.** Path dependency on the sibling repo, a git
  dependency pinned to a tag, or vendoring the (deliberately copy-pasteable) verifier modules? Leaning
  git-pinned-by-tag so verifier upgrades are explicit and reviewable.
- **Multi-trust-domain.** v1 assumes a single FerroGate trust domain per mount. Operators with several FerroGate
  environments can mount `auth/ferrogate/` more than once with different configs. Is a single mount that holds
  multiple trust anchors worth it later?
- **SPIFFE ID ↔ BastionVault identity/entity.** Should an approved machine also materialize a row in the
  identity/entity system ([identity-groups.md](identity-groups.md)) so machine tokens can join identity groups,
  or is the per-machine policy set on the enrolment record sufficient for v1? Leaning: entity mapping is a
  follow-up phase.
- **Bootstrap without root (embedded edge case).** In embedded mode is there ever a need to bootstrap the first
  machine without a root token present? Current design says no — embedded operator is root locally.

## Acceptance criteria

- **Phase-level:** each phase ships green CI + at least one integration test covering the happy path and the
  unauthorized path.
- **Feature-level:**
  - A client on a FerroGate-attested host can `bvault ferrogate login`; an unknown machine is denied with
    `403 enrolment_pending` and appears in the admin *Pending* queue.
  - An admin can `approve` from CLI **or** GUI with a chosen policy set + TTL; the machine's next `login` returns
    a token whose policies match the approval.
  - The **first** machine, presenting a valid FerroGate token **and** a BastionVault root token while no machine
    is yet approved, is auto-approved with `bootstrap_policies`; the **second** machine in the same conditions is
    *not* auto-approved (goes to `pending`).
  - A token whose SPIFFE ID/`jti` is on FerroGate's CRL is rejected (`cmis_grpc` source); a captured child token
    presented **without** a valid DPoP proof is rejected.
  - An unattested host with no FerroGate MIA cannot obtain a token at any stage.
  - `revoke` immediately invalidates active tokens for that machine via the lease manager; the next `login`
    fails with `machine_revoked`.
  - The full flow works against an HA (Hiqlite) cluster.
