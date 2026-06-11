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
| `cmis_endpoint` | CMIS `host:port` (for `cmis_grpc`). |
| `cmis_tls_enable` | `true` = hybrid PQ-TLS (`X25519MLKEM768`); `false` = cleartext (dev only). |
| `cmis_spki_pins` | SHA-384 SPKI pins of the CMIS server cert (required when TLS is on). |
| `static_jwks` | Pinned JWK set JSON (for `static_jwks`). |
| `accept_svid` | Accept a host **SVID** presented directly (weaker — no per-request DPoP). |
| `bootstrap_root_auto_approve` | One-shot first-machine bootstrap (default `true`). |
| `bootstrap_policies` | Policies granted to the bootstrapped machine (default `["default"]`). |
| `login_rate_limit_per_min` | Per-source-IP login attempts/min (`0` = unlimited; default `10`). |
| `require_user_token` | Require a `user_token` on every machine login and mint the **intersection** of machine and user policies (combined machine+user auth). Default `false`. |
| `require_machine_identity` | **Server-enforced:** every authenticated request to this server must present a machine-bound token (or a root token); plain user/token/approle sessions are rejected at the token layer. Clients discover this via the unauthenticated `auth/ferrogate/requirement` endpoint and cannot bypass it. Independent of `require_user_token` — set both for full combined enforcement. Default `false`. |

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
  `.bootstrap_approved`, `.approved`, `.login`. Denials log to the `security`
  target. Tokens and DPoP proofs are never logged.

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
- **Pending-queue flooding** — per-source-IP login rate limit.

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
