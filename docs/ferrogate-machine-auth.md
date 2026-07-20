# FerroGate Machine Authentication

The `ferrogate` auth method admits only **hardware-attested machines** whose
identity is issued by [FerroGate](https://github.com/ffquintella/FerroGate) and
**explicitly authorized by an administrator**. FerroGate answers *"is this a
real, TPM-attested machine?"*; BastionVault answers *"is this machine allowed to
use this vault?"* via an approval gate.

See the feature spec at [`features/machine-authentication.md`](../features/machine-authentication.md)
for the full design.

## How it works

1. A client on a FerroGate-attested host asks its local Machine Identity Agent
   (MIA) for a short-lived, **DPoP-bound child token** for this vault's audience.
2. It presents that token at `auth/ferrogate/login`. BastionVault verifies the
   composite (Ed25519 **and** ML-DSA-65) signature against FerroGate's published
   keys (JWKS), enforces the RFC 9449 DPoP sender-constraint, and checks the
   audience + SPIFFE trust domain.
3. A verified-but-unknown machine is recorded **pending** and denied
   (`enrolment_pending`). An administrator approves it (assigning a policy set);
   subsequent logins mint a normal BastionVault token.
4. **Bootstrap:** the first machine to authenticate while no machine is yet
   approved, presenting a BastionVault **root** token, is auto-approved (one-shot).

## Enabling and configuring

```bash
bvault auth enable ferrogate           # or the GUI: Mounts → add "FerroGate Machine Identity"
```

Configure the trust anchor (root/sudo-gated) at `auth/ferrogate/config`:

| Field | Meaning |
|---|---|
| `trust_domain` | FerroGate SPIFFE trust domain, e.g. `ferrogate.prod`. |
| `expected_audience` | This vault's audience; matched against the child token `aud`. |
| `jwks_source` | `static_jwks` (pasted keys) or `cmis_grpc` (fetch from CMIS). |
| `cmis_endpoint` | CMIS `host:port` (for `cmis_grpc`). Ignored when `cmis_srv` is set. |
| `cmis_srv` | DNS SRV owner name for a CMIS HA cluster (e.g. `_ferrogate-prod._tcp.example.com`). When set, the mount resolves it on each fetch and fails over across all advertised nodes (RFC 2782 order, per-node SPKI pin check); takes precedence over `cmis_endpoint`. |
| `cmis_tls_enable` | `true` = hybrid PQ-TLS (`X25519MLKEM768`); `false` = cleartext (dev only). |
| `cmis_spki_pins` | SHA-384 SPKI pins of the CMIS server cert (required when TLS is on). |
| `static_jwks` | Pinned JWK set JSON (for `static_jwks`). |
| `accept_svid` | Accept a host **SVID** presented directly (weaker — no per-request DPoP). |
| `bootstrap_root_auto_approve` | One-shot first-machine bootstrap (default `true`). |
| `bootstrap_policies` | Policies granted to the bootstrapped machine (default `["default"]`). |
| `login_rate_limit_per_min` | Per-source-IP login attempts/min (`0` = unlimited; default `10`). |
| `require_user_token` | Require a `user_token` on every machine login and mint the **intersection** of machine and user policies (combined machine+user auth). Default `false`. |
| `mia_environment` | MIA environment selector this deployment belongs to (e.g. `hml`): clients read `mia-<env>.toml` instead of the default `mia.toml` when dialing their local MIA for this server. Advertised on the unauthenticated `requirement` endpoint so the GUI's connect-time machine gate and combined-login binding pick the right MIA automatically. Empty = default environment. |
| `require_machine_identity` | **Server-enforced:** every authenticated request to this server must present a machine-bound token (or a root token); plain user/token/approle sessions are rejected at the token layer. Clients discover this via the unauthenticated `auth/ferrogate/requirement` endpoint and cannot bypass it. Independent of `require_user_token` — set both for full combined enforcement. Default `false`. |
| `self_enroll_enabled` | Enable the **unauthenticated** machine self-enrolment endpoint `auth/ferrogate/enroll`. Off by default. A self-enrolment only records a `pending` machine for you to approve — it never mints a token or grants access. Pre-approving a self-asserted (untrusted) SPIFFE ID is harmless on its own: real access still requires the machine to attest through `login`. |
| `self_enroll_allowlist` | Callers permitted to self-enrol. Each entry matches the **source IP** (when it parses as an IP/CIDR) or the **claimed identity** — the `spiffe_id` (exact, or a prefix ending in `*`) or the 64-hex machine id. Non-empty = only matching callers may enrol; empty = any caller (still subject to the block-list and rate limit). |
| `self_enroll_blocklist` | Callers refused self-enrolment, matched exactly like `self_enroll_allowlist`. A block-list match **always wins** over the allow-list. |
| `self_enroll_rate_limit_per_min` | Per-source-IP self-enrolment requests/min (`0` = unlimited; default `5`). Blunts flooding of the pending queue through the unauthenticated endpoint. |

> **Before enabling `require_machine_identity`:** make sure the trust anchor is configured and at least
> one machine is approved (and the admin host's MIA is reachable), or only a **root** token will be able
> to log in. Root is the break-glass path to turn it back off.

### Computing a CMIS SPKI pin

The CMIS server certificate is pinned by the SHA-384 of its SubjectPublicKeyInfo:

```bash
openssl x509 -in cmis.crt -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha384
```

Put the hex digest in `cmis_spki_pins`. (FerroGate dev CMIS uses a standard
ECDSA-P256 cert; the post-quantum part is the **key exchange**, not the cert.)

## Client and admin operations

```bash
# On an attested host (requires a running FerroGate MIA):
bvault ferrogate login --audience https://vault.example.com
bvault ferrogate status --audience https://vault.example.com
bvault ferrogate whoami

# For applications (headless): mint a machine token and print it as JSON,
# WITHOUT persisting it to the host's token helper. Exec this at app startup
# and parse the output — the token works as X-Vault-Token on direct API
# calls, or as the `machine_token` of an AppID (approle) login.
bvault ferrogate token --format json --audience https://vault.example.com
bvault ferrogate token --field client_token     # bare token, pipe-friendly

# Self-enrolment (unauthenticated): request that this machine be registered.
# Creates a PENDING record for an admin to approve; never returns a token.
# Requires self_enroll_enabled on the mount. --spiffe-id is read from the
# local MIA when omitted.
bvault ferrogate enroll --spiffe-id spiffe://ferrogate.prod/host/abc
bvault ferrogate enroll                          # derive the id from the local MIA

# Admin (GUI: Machines (FerroGate); or CLI — run against the server with a root token):
bvault operator ferrogate list --status pending
bvault operator ferrogate approve <handle|spiffe-id> --policies default,reader
bvault operator ferrogate reject <handle> --reason "unrecognised host"
bvault operator ferrogate revoke <handle>

# Server-wide enforcement: require machine identity for every session.
bvault operator ferrogate require-machine-identity          # show current value
bvault operator ferrogate require-machine-identity on       # enable
bvault operator ferrogate require-machine-identity off      # disable
```

## Observability

- **Metrics** (`/metrics`): `bvault_ferrogate_login_total`,
  `bvault_ferrogate_login_denied_total{reason=...}` (`verify_failed` / `pending`
  / `rejected` / `revoked` / `rate_limited`), `bvault_ferrogate_pending_total`,
  `bvault_ferrogate_approved_total`.
- **Audit log** (`audit` target): `ferrogate.machine.first_seen`,
  `.bootstrap_approved`, `.approved`, `.login`, `.self_enrolled`. Denials log to
  the `security` target. Tokens and DPoP proofs are never logged.

## Machine self-enrolment (unauthenticated)

When `self_enroll_enabled` is set, the mount exposes an **unauthenticated**
endpoint `POST auth/ferrogate/enroll` where an arbitrary machine can request
registration of its own (self-asserted) SPIFFE ID:

```bash
curl -X POST https://vault.example.com/v2/auth/ferrogate/enroll \
  -d '{"spiffe_id":"spiffe://ferrogate.prod/host/abc","comment":"new CI runner"}'
# → {"data":{"id":"<handle>","spiffe_id":"...","status":"pending"}}
```

The request only records a `pending` machine (badged **self-enrolled** in the
GUI queue) for an administrator to approve with the normal
`approve`/`reject`/`revoke` flow. It **never mints a token and grants no
access** — the machine still authenticates through the attested `login` flow,
so a spoofed SPIFFE ID here is inert on its own. The endpoint is guarded by:

- the `self_enroll_enabled` master switch (off by default);
- the `self_enroll_allowlist` / `self_enroll_blocklist` (block-list wins),
  matching the source IP (IP/CIDR entries) or the claimed identity; and
- the per-source-IP `self_enroll_rate_limit_per_min` limiter.

An existing record is returned unchanged — an unauthenticated caller can never
reset or downgrade an administrator's decision.

### End-to-end workflow

The self-enrolment path lets a brand-new machine put itself in front of an
administrator **without** first being pre-registered, while keeping approval a
deliberate, human-gated step. The full identification flow:

1. **Operator enables the feature.** On `auth/ferrogate/config`, set
   `self_enroll_enabled = true` (GUI: *Machines (FerroGate)* → **Config** →
   "Allow machine self-enrolment requests"). Optionally scope who may ask with
   `self_enroll_allowlist` / `self_enroll_blocklist` and tune
   `self_enroll_rate_limit_per_min`. Leave it off to keep the endpoint closed.
2. **Machine requests registration.** The machine calls the unauthenticated
   endpoint with the SPIFFE ID it claims — either directly (`curl … /enroll`) or
   via `bvault ferrogate enroll` (which reads the SPIFFE ID from the local MIA
   when `--spiffe-id` is omitted). The server applies the rate limit and
   allow/block lists, then records a `pending`, `self_enrolled` machine and
   returns `{ id, spiffe_id, status: "pending" }`. No token is issued.
3. **Administrator reviews the queue.** The request appears in the **Pending**
   tab (or `bvault operator ferrogate list --status pending`) tagged
   **self-enrolled** so it is distinguishable from admin-registered and
   attested-first-seen machines. The comment the machine supplied is shown to
   help the operator decide.
4. **Administrator approves (or rejects).** Approving attaches the machine's
   policies + TTL exactly as for any other enrolment
   (`bvault operator ferrogate approve <handle> --policies …`, or the GUI
   approve modal). Rejecting/revoking is unchanged.
5. **Machine authenticates.** The now-approved machine performs the normal
   attested login (`bvault ferrogate login`, presenting a DPoP-bound child token
   that verifies against the trust anchor). Because approval and attestation are
   both required, a self-asserted SPIFFE ID that a machine cannot actually attest
   as grants nothing even after an accidental approval.
6. **Client can poll.** Between steps 2 and 5 the machine can check its state
   with `bvault ferrogate status` (attested) or by re-calling `enroll`, which
   returns the current `status` without changing it.

## Threat model — what this does and doesn't protect

**Protects against**

- **Unattested / unknown machines** — no FerroGate token ⇒ cannot reach even
  `pending`.
- **Stolen bearer-token replay** — child tokens are DPoP sender-constrained and
  short-lived (≤ 600 s); a captured token without the matching proof is rejected.
- **Quantum (harvest-now-decrypt-later) forgery** — composite signature: an
  attacker must break **both** Ed25519 and ML-DSA-65.
- **Revoked / decommissioned hosts** — the SVID path enforces FerroGate's
  composite-signed CRL via `verify_unrevoked` (stale CRL fails closed).
- **Unauthorized-but-genuine machines** — a real attested machine still cannot
  use the vault until an admin approves its SPIFFE ID.
- **Pending-queue flooding** — per-source-IP rate limits on both `login` and the
  unauthenticated `enroll` endpoint, plus the enrol allow/block lists.
- **Self-enrolment abuse** — the unauthenticated `enroll` endpoint only creates a
  `pending` record; it mints no token, so a self-asserted SPIFFE ID grants
  nothing until an admin approves it *and* the machine can attest as that ID.

**Does NOT protect against**

- **A FerroGate compromise** — BastionVault trusts CMIS's signing key as the
  machine-identity root. Residual defense: the admin-approval gate (a forged
  SPIFFE ID is still `pending`).
- **Local privileged compromise on an approved host** — `root` there can ask the
  MIA for child tokens (subject to FerroGate's own caller allowlist). Mitigate
  with short token TTLs, admin revoke, and audit alerting on unexpected IPs.
- **Misconfigured trust anchor** — the gate is only as strong as `config`
  (config writes are root/sudo-gated and audited).

### Notes / caveats

- **`accept_svid` is weaker** than the default child-token path: a host SVID has
  no per-request DPoP sender-constraint. Prefer child tokens; enable
  `accept_svid` only for agents that can't use the MIA helper round-trip.
- **`cmis_grpc` requires the async (default) build.** With the `static_jwks`
  source the operator is responsible for refreshing the pasted keys/CRL.
- For `static_jwks`, child-token revocation relies on the short token TTL (the
  CRL is enforced on the SVID path).
