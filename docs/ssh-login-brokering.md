# SSH Login Brokering — Operator Runbook

Brokering makes every SSH login to a resource a **per-connect minted
artifact** from the SSH secret engine (a CA-signed certificate or a
one-time password) instead of a stored, shareable credential. A resource,
resource-type, or asset-group pinned to `brokered` will refuse to hold a
static SSH credential, and the ephemeral key is minted in the vault
process, never persisted, and never reaches the operator's workstation.

See the feature spec: [`features/ssh-resource-login-brokering.md`](../features/ssh-resource-login-brokering.md).

## Login classes

| Class | Meaning |
|---|---|
| `shared-credential` | A static key/password lives on the resource (the `secret` source). The historical default. |
| `brokered` | Every SSH login is minted per-connect from the SSH engine. The connection profile **must** use the `ssh-engine` credential source; no static SSH credential may be attached. |

The effective class is resolved over four tiers, **most-restrictive-wins**
(`shared-credential < brokered`); a locked upstream tier cannot be relaxed
below it by a lower tier:

1. **Global** — `ssh-broker/policy/global` (root-gated)
2. **Per-resource-type** — `ssh-broker/policy/type/<type>`
3. **Per-asset-group** — `ssh-broker/policy/asset-group/<id>`
4. **Per-resource** — `ssh-broker/policy/resource/<id>` (only writable when no upstream tier is locked)

## Pinning a resource type to brokered

```bash
# Deployment-wide default + lock (root only):
bvault ssh-broker policy set --login-class brokered --lock
bvault ssh-broker policy get

# Per-type / per-asset-group / per-resource via the logical API:
bvault write ssh-broker/policy/type/database login_class=brokered lock=true
bvault write ssh-broker/policy/resource/db01 login_class=brokered
```

Once a resource resolves to `brokered`:

- Attaching a static SSH credential (`private_key` / `password`) to it is
  refused with **`409 brokered_resource_no_static_credential`**.
- A connection profile whose `credential_source` is not `ssh-engine`
  fails the connect with **`brokered_requires_ssh_engine`** (fail-closed;
  never silently downgraded).
- The GUI profile editor disables the static `Secret` source and locks
  the credential source to the SSH secret engine.

## Target prerequisites

### CA / PQC (certificate) mode

The target `sshd` must trust the BastionVault SSH CA. Export the CA public
key and configure `TrustedUserCAKeys`:

```bash
bvault read ssh/config/ca            # copy public_key
# On the target, in /etc/ssh/sshd_config:
#   TrustedUserCAKeys /etc/ssh/bastionvault_ca.pub
# Then: systemctl reload sshd
```

The minted certificate carries the operator's identity in
`valid_principals` (intersected with the role's `allowed_users`) and in
`key_id` (the role's `key_id_format`), and is short-lived (clamped to the
role's `max_ttl`).

> **PQC note.** ML-DSA-65 (`pqc`) certs are minted by the engine for
> standalone clients, but cert-based publickey auth with an ML-DSA key is
> **not** launchable from the in-app SSH client or through the Rustion
> bastion (the `russh` client cannot present an ML-DSA-65 cert). Use `ca`
> (Ed25519) for brokered SSH logins through BastionVault / Rustion.

### OTP mode

The target host must run the `bv-ssh-helper` PAM helper, which validates
the one-time password against the vault and burns it after a single use.
OTP mode matches the target by IP against the role's `cidr_list`, so the
resource's `ip_address` (or the profile's `target_host`) must be an IP
literal.

## Forwarding through a Rustion bastion

When the resource's transport routes through a [Rustion](rustion-integration.md)
bastion (`rustion-preferred` / `rustion-required`), brokered minting
happens **server-side inside the vault**: the ephemeral keypair is
generated, signed via the bound SSH-engine role, sealed into the BVRG-v1
session-grant envelope (`ssh-cert` kind — the private key in
`credential.material`, the signed cert in `credential.extra["cert"]`), and
its plaintext copy is zeroized the instant the envelope is sealed. Rustion
decrypts the pair inside its own process and authenticates to the target
with cert-based publickey auth, recording the session. The operator's
workstation only ever holds the one-shot bastion ticket.

The session and the certificate that authorized it join on `cert_serial`,
which is stamped on `session.open` (alongside `login_class`,
`ssh_engine_mode`, and the resolved `login_class_chain`) and on the
`ssh/sign` issuance audit row on both the BastionVault and Rustion
witnesses.

> **OTP over Rustion fails closed.** The `ssh-otp` envelope kind is
> implemented, but no enrolled Rustion can yet consume it (the bastion's
> `ssh-otp` materialiser is tracked cross-repo). A brokered OTP profile
> routed through a bastion is refused with `ssh_otp_rustion_unsupported`
> rather than falling through to a direct or shared-credential path. Use
> the direct connect path for OTP brokering, or `ca` mode through Rustion.

## Composing with the Rustion transport policy

The login-class policy is structurally identical to the Rustion transport
policy and composes with it. A `database` type pinned `brokered` (locked)
plus `rustion-required` (locked) yields: *every SSH login to a database
goes through a recording bastion as a short-lived CA-signed cert tied to
the operator's identity, and no static credential may be attached* — both
controls enforced, both visible in the Connection-tab resolution chips,
neither bypassable by a resource owner.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `409 brokered_resource_no_static_credential` on secret write | The resource resolves to `brokered`. Don't store a static SSH credential; bind an `ssh-engine` source instead. |
| `brokered_requires_ssh_engine` on connect | The profile uses a non-`ssh-engine` source on a brokered resource. Switch the source to the SSH secret engine. |
| `403 login_class_locked` editing a tier | An upstream tier locked the class. Edit the locking tier (shown as `locked_at_tier`) instead. |
| `ssh_otp_rustion_unsupported` | Brokered OTP cannot route through Rustion yet. Use the direct path or `ca` mode. |
| Target rejects the cert | The target `sshd` doesn't trust the BastionVault CA. Configure `TrustedUserCAKeys`. |
