# Feature: SSH Login Brokering for Resources (cert-signing / OTP, never a shared credential)

## Summary

Let a server resource declare that SSH login is **brokered by the SSH secret
engine** — every session authenticates with a freshly-minted, short-lived
artifact (a CA-signed OpenSSH certificate, or a one-time password) instead of a
long-lived credential stored on the resource. The operator never sees a key or
password, the resource never holds one, and nothing reusable is left behind
after the session closes.

Two halves:

1. **Resource-bound SSH brokering.** A resource gains an explicit
   **login class** for its SSH connection profiles: `shared-credential` (the
   existing `secret` source — a static key / password lives on the resource) or
   **`brokered`** (the credential is minted per-connect from a bound SSH-engine
   role in `ca`, `pqc`, or `otp` mode). A resource — or a whole resource type /
   asset group — can be **pinned to `brokered`**, after which the GUI and API
   refuse to attach or reveal a static SSH credential on it. This turns the
   `ssh-engine` credential source that [Resource Connect](resource-connect.md)
   already ships from an *option an operator may pick* into a *policy an admin
   can mandate*.

2. **Forwarding the minted certificate to Rustion.** When the resource's
   transport is a [Rustion](rustion-integration.md) bastion, the brokered
   artifact is sealed into the session-grant envelope so **Rustion** performs
   the publickey/cert authentication to the target on the operator's behalf.
   This adds an `ssh-cert` (key + signed certificate) and `ssh-otp` credential
   kind to the BVRG-v1 envelope, closing the gap the Rustion integration
   documents today: *"non-password SSH … under `rustion-required` fails closed
   pending the bastion's PKINIT path."* The operator's workstation never holds
   the certificate; the bastion authenticates with it and records the session.

Net effect: a regulated environment can declare *"every SSH login to a
`database` resource is a short-lived CA-signed certificate, minted per session,
forwarded through a recording bastion, and tied to the operator's identity in
the cert's principals and key-id"* — with no static credential anywhere in the
path.

## Motivation

- **Stop storing shareable SSH credentials.** Even with masked reveal, a
  resource that carries a static SSH key / password is a credential that *can*
  be copied, shared, and outlive the operator's authorization. The SSH engine
  was built to eliminate exactly this ([features/ssh-secret-engine.md](ssh-secret-engine.md))
  — but a resource can still be configured with a static `secret` source today.
  This feature lets an admin forbid that per-resource and force every login
  through the engine.
- **Make "no shared credential" auditable and enforceable, not just available.**
  Resource Connect already *supports* the `ssh-engine` source; nothing *requires*
  it. A `login_class = brokered` pin (lockable at the resource-type / asset-group
  tier, mirroring the four-tier transport policy in the Rustion integration)
  turns an available good practice into an enforced control with an explicit,
  observable failure mode when violated.
- **Close the bastion's non-password SSH gap.** The [Rustion integration](rustion-integration.md)
  routes SSH-*password* and RDP-*password* through the bastion but fails closed
  for certificate-based SSH under `rustion-required`. Forwarding a minted cert
  (ephemeral key + signed certificate) inside the envelope lets Rustion do
  cert-based publickey auth to the target — so the strongest, non-shared SSH
  credential is also the one that works through the recording bastion.
- **Bind the session to the operator's identity end to end.** A brokered cert
  carries the operator's identity in `valid_principals` and `key_id`
  (`ssh/sign`'s `key_id_format` already templates `{{identity.entity.id}}`).
  That identity rides the BVRG envelope into Rustion's hash-chained recording
  and back into BastionVault's audit chain — so "who held a shell on `db01` at
  03:14, and under what certificate serial?" is answerable from either witness.
- **Ephemeral keys never touch the operator's disk.** For the brokered path
  BastionVault mints the ephemeral keypair, signs it, seals **both** halves into
  the envelope, and drops the private half from its own memory once sealed.
  Neither the operator's workstation nor the resource record ever holds it.

## Current State

**Phases 1–4 implemented; Phase 5 partially implemented.** The four-tier
`login_class` policy, attach-time `409` enforcement, direct-path
`brokered_requires_ssh_engine` rejection, the `ssh-cert` / `ssh-otp`
envelope kinds, server-side brokered minting on the Rustion path
(ephemeral key minted + sealed + zeroized in-process), and the
`session.open` audit fields (`login_class`, `ssh_engine_mode`,
`cert_serial`, `login_class_chain`) are live. CLI `bvault ssh-broker
policy {get,set}` and the connection-profile editor's brokered gate ship.
Covered by unit tests (login-class resolver, envelope `ssh-cert`
round-trip, GUI gating helpers) and a host integration test
(`brokered_enforcement_tests`: `409` attach guard, effective resolution,
`403` lock violation).

**Not yet implemented:** the Rustion-side `ssh-otp` session materialiser
(tracked cross-repo — `ssh-cert` already works against Rustion v0.11.0;
brokered OTP over Rustion fails closed with `ssh_otp_rustion_unsupported`);
the direct-path testcontainers `ca` round-trip + the
`tests/e2e/rustion-ssh/` end-to-end forwarding test; the standalone
resource-detail brokered badge and the full per-tier policy editor in the
GUI (the four tiers are manageable via CLI + the `ssh-broker/policy/*`
API today); the operator runbook in `docs/`.

### Pre-existing building blocks

- The [SSH secret engine](ssh-secret-engine.md) ships CA-signed certs
  (Ed25519), OTP (with the `bv-ssh-helper` target binary), and ML-DSA-65 PQC
  certs, plus per-issuance audit. `ssh/sign/<role>`, `ssh/creds/<role>`, and
  `ssh/verify` are live.
- [Resource Connect](resource-connect.md) ships an `ssh-engine` credential
  source (`SshEngineMode { Ca, Otp, Pqc }`) on `ConnectionProfile`, resolved
  host-side at connect time; it landed in 0.7.11. Today it is one of four
  selectable sources (`Secret` / `Ldap` / `SshEngine` / `Pki`) with **no policy
  that can require it** over `Secret`.
- The [Rustion integration](rustion-integration.md) ships the BVRG-v1 envelope
  with `credential.kind ∈ { ssh-key, ssh-password, rdp-password, rdp-cert }` and
  routes SSH-password / RDP-password sessions through the bastion (Phase 7.4).
  Per the roadmap: *non-password SSH and smart-card RDP under `rustion-required`
  **fail closed** pending the bastion's PKINIT path.* There is **no** envelope
  kind that carries a signed SSH certificate + its ephemeral private key.
- There is no per-resource notion of a **login class** — nothing distinguishes
  "this resource uses a stored credential" from "this resource only ever uses a
  minted one," and nothing can forbid the former.

## Scope

### In scope

- **`login_class` on SSH connection profiles** — `shared-credential` |
  `brokered`. `brokered` requires the profile's `credential_source` to be
  `SshEngine` (any mode) and rejects `Secret` for the SSH key/password fields.
- **Four-tier `login_class` policy**, evaluated **most-restrictive-wins**
  (`shared-credential < brokered`), mirroring the Rustion transport tiers so the
  two policies compose cleanly:
  1. **Global default** — `sys/config/ssh-broker` (`login_class_default`,
     `login_class_lock`).
  2. **Per-resource-type** — `connect.login_class` on `ResourceTypeDef`.
  3. **Per-asset-group** — `connect.login_class` on an [asset group](asset-groups.md).
  4. **Per-resource** — on the resource record, editable only when no upstream
     tier is locked.
  A locked upstream tier makes the field read-only in the GUI and returns
  `403 login_class_locked` (with `locked_at_tier`) from the API, exactly like
  `transport_locked`.
- **Enforcement at credential attach time** — when a resource resolves to
  `brokered`, the resource API rejects creating / updating a credential-shaped
  secret intended for SSH on it (`409 brokered_resource_no_static_credential`),
  and the GUI hides the "static SSH credential" editor for that resource. Any
  pre-existing static SSH secret is surfaced with a "remove — this resource is
  brokered" banner and is **never** offered to the SSH dialler.
- **Brokered SSH credential resolver (direct path)** — at connect time, for a
  `brokered` profile bound to an SSH-engine role:
  - **`ca` / `pqc` mode** — BastionVault generates an **ephemeral** client
    keypair (algorithm matching the role, Ed25519 default / ML-DSA-65 for `pqc`),
    calls `ssh/sign/<role>` with the ephemeral public key + the operator's
    identity-templated principals, and feeds the `(ephemeral_private_key,
    certificate)` pair to the local `russh` dialler for cert-based publickey
    auth. The ephemeral private key lives only in host memory
    (`Zeroizing`), is never persisted, and is dropped on session close.
  - **`otp` mode** — BastionVault calls `ssh/creds/<role>` for a one-time
    password and drives a password-auth login; the target's `bv-ssh-helper`
    consumes it once.
- **`ssh-cert` and `ssh-otp` envelope kinds (Rustion path)** — extend BVRG-v1's
  `credential.kind` with:
  - **`ssh-cert`** — `material` carries the ephemeral **private key** (PEM,
    zeroized after sealing) and the signed **OpenSSH certificate**; `username`
    carries the principal. Rustion decrypts inside its own process and presents
    the (key, cert) pair to the target `sshd` as publickey/cert auth. The
    operator's workstation only ever sees the one-shot ticket.
  - **`ssh-otp`** — `material` carries the one-time password + target metadata;
    Rustion drives the password-auth + helper dance to the target.
  In both cases the artifact is minted **per envelope** with a TTL ≤ the role's
  `max_ttl`, and the ephemeral private key is dropped from BastionVault memory
  the instant the envelope is sealed.
- **Identity binding** — brokered certs always carry the operator's identity in
  `valid_principals` (subject to the role's `allowed_users`) and `key_id`
  (the role's `key_id_format`, default already templates the entity id). The
  resolved serial is recorded on `session.open` (and on the SSH-sign audit row
  that already exists), so a session and the certificate that authorized it are
  joinable in audit.
- **Audit** — `session.open` gains `login_class`, `ssh_engine_mode`
  (`ca|pqc|otp`), `cert_serial` (cert modes), and `login_class_chain` (the
  resolved tier chain). New config-change events
  `ssh_broker.policy.{global,type,asset_group,resource}.update`. The existing
  `ssh/sign` issuance audit row is correlated to the session via `cert_serial`.
- **GUI** — the Connection tab shows the effective `login_class` and its source
  tier ("brokered ← resource-type `database` (locked)"); the profile editor
  disables the `Secret` SSH source and pre-selects `SshEngine` when the resource
  is brokered; the resource detail shows a "Brokered — no static SSH credential
  stored" badge.
- **CLI** — `bvault ssh-broker policy {get,set}` for the global tier;
  per-resource / per-type / per-group via the existing resource / type /
  asset-group editors.

### Out of scope (explicit)

- **RDP brokering / PKINIT smart-card forwarding.** This feature is SSH-only.
  The `rdp-cert` smart-card-through-bastion path stays tracked in the
  [Rustion integration](rustion-integration.md) (its PKINIT/SPNEGO track).
- **Dynamic-keys SSH mode** (pushing a key to `authorized_keys` over outbound
  SSH). Still deferred with the rest of the SSH engine's dynamic-keys mode,
  pending the [dynamic-secrets](dynamic-secrets.md) framework.
- **A new key-management subsystem.** Ephemeral keypairs are minted in-process
  with the existing crypto crate and never persisted; there is no new at-rest
  key store.
- **Changing the SSH engine's wire surface.** `ssh/sign`, `ssh/creds`,
  `ssh/verify` are reused as-is. The only new server surface is the
  `sys/config/ssh-broker` policy and the resolver glue.
- **Rotating-on-close static credentials.** Brokered credentials are ephemeral
  by construction, so there is nothing to rotate; static-credential rotation
  remains the operator's existing schedule (unchanged from Resource Connect).
- **Host-key / bastion TLS pinning changes.** Inherited unchanged from Resource
  Connect (TOFU on the target) and the Rustion integration (pinned bastion
  identity).

## Design

### Login class on the connection profile

`ConnectionProfile` ([resource-connect.md](resource-connect.md) Phase 2) gains a
`login_class` discriminator that constrains the allowed `credential_source`:

```rust
pub enum SshLoginClass {
    /// A static key / password lives on the resource (the `Secret` source).
    SharedCredential,
    /// Every login is minted per-connect from the SSH engine. The
    /// `credential_source` MUST be `SshEngine { .. }`; `Secret` is rejected.
    Brokered,
}

pub struct ConnectionProfile {
    // ...existing fields (id, name, protocol, target_*, username,
    //    credential_source, host_key_pin, allow_legacy_auth)...

    /// SSH only. Defaults to the resolved tier policy (see below). Ignored
    /// for RDP profiles.
    pub login_class: Option<SshLoginClass>,
}
```

Resolution at connect time:

1. Resolve the effective `login_class` from the four tiers
   (`min(global, type, asset-group, resource)` under
   `shared-credential < brokered`, locked upstream tiers cannot be relaxed).
2. If the resolved class is `brokered`, require `credential_source ==
   SshEngine { .. }`. A profile whose source is `Secret` is **invalid** and the
   connect attempt fails with `brokered_requires_ssh_engine` (the GUI prevents
   constructing such a profile in the first place; the API rejects it on write).
3. Mint and dial per the mode (below).

### Brokered minting — direct path

```
operator clicks Connect (brokered profile, ca mode)
        │
        ▼
host generates ephemeral keypair  (Ed25519 / ML-DSA-65, in-memory, Zeroizing)
        │
        ▼
host → ssh/sign/<role>  { public_key, valid_principals = <operator principal>,
                          ttl ≤ role.max_ttl }
        │
        ▼  { signed_key (OpenSSH cert), serial_number }
        ▼
russh authenticate_publickey( ephemeral_priv + cert )   ── direct TCP ──▶ target sshd
        │                                                  (TrustedUserCAKeys)
        ▼
session.open { login_class: "brokered", ssh_engine_mode: "ca",
               cert_serial: <serial>, ... }
```

OTP mode replaces the sign call with `ssh/creds/<role>` and a password-auth
dial; the target's `bv-ssh-helper` consumes the OTP exactly once
(unchanged from the SSH engine's Phase 2 contract).

### Brokered minting — Rustion path (cert forwarding)

The credential-source resolver is unchanged; only what happens *after* minting
differs. For a `rustion` transport the minted artifact is sealed into the
BVRG-v1 envelope instead of dialled locally:

```
host generates ephemeral keypair + ssh/sign/<role>  (as above)
        │
        ▼
envelope payload.credential = {
    kind: "ssh-cert",
    username: "<principal>",
    material: { private_key: <ephemeral PEM>, certificate: <OpenSSH cert> },
    extra:    { cert_serial, role, mode: "ca" | "pqc" }
}
        │   sign(master_priv, encrypt(rustion_pub, cbor(payload)))
        ▼
POST /v1/sessions  ───────────────▶  Rustion
        │                            verify + decrypt (only Rustion sees the key)
        ▼  { sid, host, port, ticket, expires_at }
operator GUI ── ticket@sid ──▶ Rustion ── publickey/cert auth ──▶ target sshd
                                          (records the session)
```

`ssh-otp` is identical except `material` carries the one-time password and
Rustion drives password-auth to the target.

**Envelope additions (BVRG-v1, no version bump — `credential.kind` is an open
string union):**

| `kind` | `material` | Who authenticates to the target |
|---|---|---|
| `ssh-cert` | `{ private_key: PEM, certificate: OpenSSH-cert }` | Rustion, publickey/cert auth |
| `ssh-otp`  | `{ otp: string, ip, port }` | Rustion, password auth + target `bv-ssh-helper` |

The ephemeral private key is the only long-ish-lived secret in the envelope and
it is **ephemeral by construction** (minted for this one envelope, TTL ≤
`max_ttl`); BastionVault zeroizes its copy the instant the ciphertext is sealed.
Replay protection is the envelope's existing `nonce` + Rustion's sliding window.

**Rustion-side (new control-plane behavior):** the session materialiser learns
two new credential kinds. For `ssh-cert` it loads the `(private_key,
certificate)` pair into its SSH client and authenticates to the target with
cert-based publickey auth (the target must trust the BastionVault SSH CA via
`TrustedUserCAKeys`, the same prerequisite as the direct path). For `ssh-otp` it
drives password auth and relies on the target's `bv-ssh-helper`. This is the
symmetric Rustion-side work that retires the "non-password SSH fails closed under
`rustion-required`" caveat.

### `login_class` policy tiers

`sys/config/ssh-broker` (root-only writes), `connect.login_class` on
`ResourceTypeDef` (admin), on the asset group (admin / group owner), and on the
resource (owner, when unlocked). Resolution and lock semantics are a direct copy
of the Rustion transport policy's machinery — same `locked_at_tier` error body,
same "nearest-tier-wins for non-monotone fields, most-restrictive-wins for the
class itself," same Connection-tab resolution chip. Keeping the two policies
structurally identical means an admin reasons about one model, not two.

A worked composition: a `database` resource type pinned `brokered` (locked) plus
the Rustion integration's `rustion-required` (locked) yields *"every SSH login to
a database goes through a recording bastion as a short-lived CA-signed cert tied
to the operator's identity, and no static credential may be attached"* — both
controls enforced, both visible in the resolution chip, neither bypassable by a
resource owner.

### Module / file layout (planned)

```
src/modules/resource/ssh_broker_policy.rs   -- login_class tiers + resolver + lock errors
src/modules/system/path_config_ssh_broker.rs -- sys/config/ssh-broker CRUD (root)
gui/src-tauri/src/session/credential.rs      -- (extend) brokered minting; ephemeral keypair + ssh/sign
gui/src-tauri/src/rustion/envelope.rs        -- (extend) ssh-cert / ssh-otp credential kinds
gui/src/components/ConnectionProfileEditor.tsx -- (extend) login_class gating, disable Secret when brokered
gui/src/routes/ResourcesPage.tsx             -- (extend) brokered badge + locked-tier chip
gui/src/lib/sshBrokerApi.ts                  -- thin wrappers for the policy commands
```

(Cross-repo: the matching `ssh-cert` / `ssh-otp` session materialiser in
Rustion's control plane, tracked in lockstep the same way the rest of the
integration is.)

## Phases

### Phase 1 — `login_class` on profiles + per-resource enforcement — ✅ Done

| Deliverable | Location |
|---|---|
| `SshLoginClass` + `login_class` field on `ConnectionProfile` | `src/modules/resource/` |
| Connect rejects `brokered` + `Secret` source (`brokered_requires_ssh_engine`) | host resolver |
| Credential-attach guard: `409 brokered_resource_no_static_credential` | `src/modules/resource/` |
| GUI: disable `Secret` SSH source + pre-select `SshEngine` when brokered; brokered badge | `ConnectionProfileEditor.tsx`, `ResourcesPage.tsx` |
| Tests: brokered profile rejects static cred attach; ca/otp profile accepted | host + vitest |

### Phase 2 — Four-tier `login_class` policy + lock — ✅ Done

| Deliverable | Location |
|---|---|
| `sys/config/ssh-broker` global tier (`login_class_default`, `login_class_lock`), root-gated | `src/modules/system/path_config_ssh_broker.rs` |
| `connect.login_class` on `ResourceTypeDef` + asset group + resource record | resource / type / asset-group editors |
| Resolver (`min` under `shared-credential < brokered`) + `403 login_class_locked` w/ `locked_at_tier` | `ssh_broker_policy.rs` |
| GUI resolution chip + read-only field when an upstream tier is locked | Connection tab |
| `bvault ssh-broker policy {get,set}` CLI | CLI |
| Policy-change audit events | host |

### Phase 3 — Brokered minting on the direct connect path — ✅ Done (testcontainers round-trip pending)

| Deliverable | Location |
|---|---|
| Ephemeral keypair mint (Ed25519 / ML-DSA-65, `Zeroizing`) + `ssh/sign/<role>` call | `gui/src-tauri/src/session/credential.rs` |
| `russh` cert-based publickey auth with the minted `(key, cert)` | `gui/src-tauri/src/session/ssh.rs` |
| OTP-mode path via `ssh/creds/<role>` + password auth (helper-consumed) | `credential.rs` |
| `session.open` carries `login_class` / `ssh_engine_mode` / `cert_serial`; correlated to the existing `ssh/sign` audit row | `session/audit.rs` |
| Integration test (testcontainers OpenSSH w/ `TrustedUserCAKeys`): brokered `ca` round-trip; ephemeral key never persisted; OTP single-use | `gui/src-tauri/tests/` |

### Phase 4 — `ssh-cert` / `ssh-otp` envelope forwarding to Rustion — ✅ Done (BastionVault side; Rustion `ssh-otp` materialiser + `tests/e2e/rustion-ssh/` pending cross-repo)

| Deliverable | Location |
|---|---|
| BVRG-v1 `ssh-cert` + `ssh-otp` credential kinds (seal ephemeral key + cert; zeroize after seal) | `gui/src-tauri/src/rustion/envelope.rs` |
| Rustion-transport brokered path seals the minted artifact instead of dialling locally | `credential.rs` + dispatcher |
| Retire the `rustion-required` non-password-SSH fail-closed branch | connect button policy resolver |
| **(Rustion repo)** control-plane session materialiser handles `ssh-cert` (cert publickey auth) + `ssh-otp` | cross-repo |
| e2e through the `tests/e2e/rustion-ssh/` stack: brokered cert forwarded → bastion authenticates to target → session recorded → `cert_serial` on both audit witnesses | `tests/e2e/rustion-ssh/` |

### Phase 5 — Polish

| Deliverable | Location |
|---|---|
| Connection-tab combined chip (login_class ⊕ transport ⊕ recording, each with its locking tier) | `ResourcesPage.tsx` |
| Pre-existing static SSH secret on a now-brokered resource: "remove — brokered" banner; never offered to the dialler | `ResourcesPage.tsx` + resolver |
| Docs: operator runbook (target `TrustedUserCAKeys` prereq, OTP helper, bastion forwarding) | `docs/` |

## Dependencies

No new crates. Reuses `russh` / `russh-keys` (Resource Connect), the SSH engine's
`ssh/sign` + `ssh/creds`, `bastion-vault-crypto` (envelope), and the Rustion
control-plane client. The only cross-repo dependency is Rustion's new `ssh-cert`
/ `ssh-otp` session-materialiser support.

## Security Considerations

- **No static SSH credential on brokered resources.** Enforced at attach time
  (not just hidden in the GUI): a brokered resource returns
  `409 brokered_resource_no_static_credential` on any attempt to store an SSH
  key/password, and a pre-existing one is never handed to the dialler.
- **Ephemeral private key never persists, never reaches JS, never reaches the
  operator's disk.** For both the direct and the Rustion path, BastionVault mints
  the keypair in host memory, wraps it in `Zeroizing`, and drops it on session
  close (direct) or the instant the envelope is sealed (Rustion). The JS layer
  only ever holds the session token / one-shot ticket.
- **The certificate is the short-lived artifact.** TTL is clamped to the role's
  `max_ttl` (the SSH engine already enforces this); there is no infinite-TTL
  brokered mode. A leaked envelope is bounded by the cert's validity window and
  the envelope's own `not_after` + `nonce` replay window.
- **Identity binding is mandatory.** Brokered certs always carry the operator
  principal (intersected with `allowed_users`) and an identity-templated
  `key_id`, so the certificate, the session, and the audit witnesses on both
  BastionVault and Rustion all join on the same operator + serial.
- **Rustion decrypts the credential, the operator does not.** On the Rustion
  path the `(key, cert)` pair is ML-KEM-768-sealed to Rustion's pinned pubkey and
  only decrypted inside Rustion's process — the credential's sole out-of-vault
  landing site is Rustion's authentication to the target.
- **Fail closed on misconfiguration.** A `brokered` profile with a `Secret`
  source is rejected, not silently downgraded. A `rustion-required` + `brokered`
  resource whose bastion can't perform cert auth fails with an explicit error
  rather than falling back to a direct or shared-credential path.
- **No new crypto, no OpenSSL / `aws-lc-sys`.** Inherits the SSH engine and
  envelope crypto stacks unchanged.

## Testing Requirements

- **Unit** — `login_class` tier resolution (`min` ordering, locked-tier refusal,
  `locked_at_tier` body); `brokered` + `Secret` rejected; envelope `ssh-cert` /
  `ssh-otp` CBOR round-trip with the ephemeral key zeroized after seal.
- **Integration (direct)** — testcontainers OpenSSH with `TrustedUserCAKeys`:
  brokered `ca` round-trip succeeds; assert the ephemeral key is never written to
  disk and is zeroized after close; OTP single-use (replay fails).
- **Integration (Rustion)** — through `tests/e2e/rustion-ssh/`: a brokered cert
  is forwarded in the envelope, the bastion authenticates to the target, the
  session is recorded, and `cert_serial` appears on both audit witnesses; a
  bastion that can't do cert auth surfaces a clean error, not a fallthrough.
- **Negative** — attach static SSH cred to a brokered resource → `409`; operator
  tries to relax a locked `brokered` tier → `403 login_class_locked`; tampering
  the forwarded cert (flip a signature byte) → target auth fails, `session.open`
  not emitted.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md),
and this file's "Current State" / phase markers. The Rustion-side
`ssh-cert` / `ssh-otp` materialiser is tracked in lockstep with the
[Rustion integration](rustion-integration.md) cross-repo phases.
