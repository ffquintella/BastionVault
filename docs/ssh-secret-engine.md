# SSH Secret Engine

BastionVault's SSH engine issues short-lived SSH credentials so operators stop pasting long-lived `~/.ssh/id_*` keys onto target hosts. It supports two modes:

- **CA mode** — BastionVault signs operator-supplied client public keys, returning OpenSSH certificates with role-bound principals, TTL, extensions, and critical options.
- **OTP mode** — BastionVault mints a single-use password that a helper on the target host validates over the wire.

The engine is pure-Rust (no OpenSSL). Ed25519 is the classical CA algorithm; ML-DSA-65 (`ssh-mldsa65@openssh.com`) is available under the `ssh_pqc` build feature for post-quantum end-to-end chains.

This page covers the operator workflow: enable the mount, configure the CA, define roles, and let users sign / mint credentials. See [features/ssh-secret-engine.md](https://github.com/ffquintella/BastionVault/blob/main/features/ssh-secret-engine.md) for the design history and phased rollout.

---

## 1. Permissions

The engine is mounted at a path (typically `ssh/`). Operators need an admin policy to mount and configure; end users need a narrower policy to sign / mint OTPs.

### Admin policy

```hcl
# ssh-admin.hcl — mount, CA, roles, tidy
path "sys/mounts/ssh" {
  capabilities = ["create", "read", "update", "delete", "sudo"]
}
path "sys/mounts" {
  capabilities = ["read"]
}
path "ssh/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
```

### End-user policy (CA mode, sign-only)

```hcl
# ssh-user.hcl — sign certs under a specific role
path "ssh/sign/web-admins" {
  capabilities = ["create", "update"]
}
path "ssh/public_key" {
  capabilities = ["read"]
}
path "ssh/roles" {
  capabilities = ["list"]
}
path "ssh/roles/web-admins" {
  capabilities = ["read"]
}
```

### End-user policy (OTP mode)

```hcl
# ssh-otp-user.hcl — mint a one-time password
path "ssh/creds/legacy-servers" {
  capabilities = ["create", "update"]
}
path "ssh/lookup" {
  capabilities = ["create", "update"]
}
```

Apply with:

```bash
bv policy write ssh-admin ssh-admin.hcl
bv policy write ssh-user ssh-user.hcl
```

---

## 2. Enable the engine

The engine type is `ssh`. Mount once per logical environment (e.g. `ssh/` for production, `ssh-staging/` for staging).

### CLI

```bash
bvault secrets enable --path=ssh ssh
```

### HTTP

```bash
curl -sS -H "X-Vault-Token: $BV_TOKEN" \
     -X POST \
     -d '{"type":"ssh"}' \
     https://vault.example.com/v1/sys/mounts/ssh
```

### GUI

Navigate to **SSH** in the sidebar (visible to admins when an `ssh/` mount exists, or use the "+ Mount SSH engine" button when no mount is present yet).

---

## 3. Configure the CA (CA mode)

Generate a fresh CA keypair, or import an existing OpenSSH private key. The public key is exposed at `/v1/ssh/public_key` so target hosts can pin it as a `TrustedUserCAKeys`.

### Generate Ed25519 (default)

```bash
bv write ssh/config/ca generate_signing_key=true
```

```bash
curl -sS -H "X-Vault-Token: $BV_TOKEN" \
     -X POST \
     -d '{"generate_signing_key":true}' \
     https://vault.example.com/v1/ssh/config/ca
```

Response carries `public_key` (OpenSSH format) and `algorithm` (`ssh-ed25519`).

### Generate ML-DSA-65 (post-quantum, build with `--features ssh_pqc`)

```bash
bv write ssh/config/ca generate_signing_key=true algorithm=mldsa65
```

### Import an existing CA

```bash
bv write ssh/config/ca \
  generate_signing_key=false \
  private_key=@/path/to/openssh-ed25519-key
```

`private_key` accepts an unencrypted OpenSSH-format Ed25519 private key.

### Pin the CA on target hosts

```bash
# Read the CA public key
bv read -field=public_key ssh/public_key > /etc/ssh/bv_user_ca.pub

# /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/bv_user_ca.pub
```

Reload `sshd` once the file is in place. Hosts now accept any certificate signed by this CA whose `valid_principals` includes a real local user.

### Delete the CA

```bash
bv delete ssh/config/ca
```

Existing signed certificates remain valid until their TTL expires; new signs fail with `ssh CA not configured`.

---

## 4. Define a CA-mode role

A role pins **what kind of certificate the engine will sign**: which principals are allowed, which extensions / critical options the caller may request, default TTL, and whether the chain must be PQC end-to-end.

### Minimal example — web admins, 30-minute certs

```bash
bv write ssh/roles/web-admins \
  key_type=ca \
  algorithm_signer=ssh-ed25519 \
  cert_type=user \
  default_user=webops \
  allowed_users="webops,deploy" \
  allowed_extensions="permit-pty,permit-agent-forwarding" \
  default_extensions=permit-pty=true \
  ttl=30m \
  max_ttl=2h
```

### Locked-down host-cert role for an SSH bastion

```bash
bv write ssh/roles/bastion-host \
  key_type=ca \
  cert_type=host \
  allowed_users="bastion.prod.example.com,*.bastion.prod.example.com" \
  default_extensions= \
  ttl=720h \
  max_ttl=8760h
```

`cert_type=host` produces a host certificate; `valid_principals` becomes the hostnames the cert authenticates.

### PQC end-to-end role

```bash
bv write ssh/roles/pqc-deploy \
  key_type=ca \
  algorithm_signer=ssh-mldsa65@openssh.com \
  default_user=deploy \
  allowed_users=deploy \
  pqc_only=true \
  ttl=15m
```

`pqc_only=true` rejects sign requests where the client public key is classical, forcing the entire chain (client → CA) onto ML-DSA-65. Requires a PQC CA and a PQC-aware client.

### Role fields reference

| Field | Default | Notes |
|---|---|---|
| `key_type` | `ca` | `ca` for cert signing, `otp` for one-time passwords. |
| `algorithm_signer` | `ssh-ed25519` | Today: `ssh-ed25519` or `ssh-mldsa65@openssh.com`. |
| `cert_type` | `user` | `user` or `host`. |
| `allowed_users` | _empty_ | Comma list; `*` allows any principal. |
| `default_user` | _empty_ | Used when caller omits `valid_principals`. |
| `allowed_extensions` | _empty_ | Whitelist filter applied to caller-supplied `extensions`. |
| `default_extensions` | _empty_ | Always-on extensions, even if not requested. |
| `allowed_critical_options` | _empty_ | Whitelist filter (e.g. `force-command`, `source-address`). |
| `default_critical_options` | _empty_ | Always-on critical options. |
| `ttl` | engine default | Role default validity. |
| `max_ttl` | engine default | Hard cap; per-call requests above this are clamped. |
| `not_before_duration` | `30s` | Backdates `valid_after` for client–server clock skew. |
| `key_id_format` | `vault-{{identity.entity.id}}-{{role}}-{{token_display_name}}` | Template for the cert's `key id`. |
| `pqc_only` | `false` | Reject classical client keys, even if the CA is PQC. |

### List / read / delete roles

```bash
bv list ssh/roles
bv read ssh/roles/web-admins
bv delete ssh/roles/web-admins
```

---

## 5. Sign a client public key (user workflow)

Operators generate a local keypair, submit the public key to BastionVault, and load the returned certificate into `ssh-agent` (or pass it via `-i`).

```bash
# 1) Local ephemeral keypair (no passphrase — the cert is short-lived)
ssh-keygen -t ed25519 -f ~/.ssh/bv -N "" -C "bv-temp"

# 2) Sign it under the role
bv write -field=signed_key ssh/sign/web-admins \
  public_key=@~/.ssh/bv.pub \
  valid_principals=webops \
  ttl=30m \
  > ~/.ssh/bv-cert.pub

# 3) Use it
ssh -i ~/.ssh/bv -o CertificateFile=~/.ssh/bv-cert.pub webops@web-01.prod.example.com
```

Equivalent HTTP request:

```bash
curl -sS -H "X-Vault-Token: $BV_TOKEN" \
     -X POST \
     -d @- \
     https://vault.example.com/v1/ssh/sign/web-admins <<EOF
{
  "public_key": "$(cat ~/.ssh/bv.pub)",
  "valid_principals": "webops",
  "ttl": "30m",
  "extensions": {"permit-pty": ""}
}
EOF
```

Response fields:

```json
{
  "data": {
    "serial_number": "12345",
    "signed_key": "ssh-ed25519-cert-v01@openssh.com AAAA…"
  }
}
```

Extensions and critical options the caller requests are intersected with the role's whitelist; anything outside the whitelist is silently dropped (the cert still issues, just without the rejected entry).

### Sign for a host certificate

```bash
bv write -field=signed_key ssh/sign/bastion-host \
  public_key=@/etc/ssh/ssh_host_ed25519_key.pub \
  cert_type=host \
  valid_principals="bastion-01.prod.example.com,bastion-02.prod.example.com" \
  ttl=720h \
  > /etc/ssh/ssh_host_ed25519_key-cert.pub
```

Then in `sshd_config`:

```
HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
```

---

## 6. OTP mode (legacy hosts)

Use OTP mode where the target host can't trust an SSH CA (older systems, appliances). The flow:

1. User asks BastionVault for an OTP scoped to `(role, ip, username)`.
2. User runs `ssh user@host`.
3. The `bv-ssh-helper` on the host captures the password via PAM, validates it against BastionVault, and lets the session through exactly once.

### Define an OTP role

```bash
bv write ssh/roles/legacy-servers \
  key_type=otp \
  default_user=admin \
  cidr_list="10.10.0.0/16,192.168.5.0/24" \
  exclude_cidr_list="10.10.99.0/24" \
  port=22
```

`cidr_list` / `exclude_cidr_list` validate the requested target IP at mint time — a request outside the allow-list is refused with a clear error.

### Mint an OTP

```bash
bv write ssh/creds/legacy-servers \
  ip=10.10.4.17 \
  username=admin \
  ttl=2m
```

Response (the plaintext password is returned exactly once):

```json
{
  "data": {
    "key": "VLm4Q9zXc7…",
    "key_type": "otp",
    "username": "admin",
    "ip": "10.10.4.17",
    "port": 22
  }
}
```

### Helper installation on the target host

```bash
# 1) Ship the helper binary
sudo install -m 0755 bv-ssh-helper /usr/local/bin/bv-ssh-helper

# 2) Tell it where the vault is — /etc/bv-ssh-helper.conf
sudo tee /etc/bv-ssh-helper.conf <<'EOF'
VAULT_ADDR=https://vault.example.com
SSH_MOUNT=ssh
EOF
sudo chmod 0644 /etc/bv-ssh-helper.conf

# 3) PAM glue — /etc/pam.d/sshd, before the existing 'auth' lines
auth requisite pam_exec.so quiet expose_authtok log=/var/log/bv-ssh-helper.log /usr/local/bin/bv-ssh-helper
auth optional  pam_unix.so not_set_pass use_first_pass nodelay

# 4) sshd_config — force PAM, allow keyboard-interactive
ChallengeResponseAuthentication yes
UsePAM yes
PasswordAuthentication no
```

Reload `sshd`. The next `ssh admin@10.10.4.17` prompt will accept the OTP and consume it on the BastionVault side.

### Look up which OTP roles match a host

Sometimes a user knows the host they need but not the role. `lookup` returns the role names without consuming a credential:

```bash
bv write ssh/lookup ip=10.10.4.17 username=admin
```

```json
{
  "data": {
    "roles": ["legacy-servers"]
  }
}
```

### Verify (helper-side; operators rarely call this directly)

```bash
curl -sS -H "X-Vault-Token: $HELPER_TOKEN" \
     -X POST \
     -d '{"otp":"VLm4Q9zXc7…"}' \
     https://vault.example.com/v1/ssh/verify
```

The helper's token needs `create` on `ssh/verify` only — keep it scoped:

```hcl
path "ssh/verify" { capabilities = ["create", "update"] }
```

---

## 7. Audit-log redaction

The audit subsystem redacts these fields automatically, so operators can keep request/response logging on without leaking credentials:

| Endpoint | Redacted field(s) |
|---|---|
| `ssh/sign/<role>` (response) | `signed_key` |
| `ssh/issue/<role>` (response) | `private_key`, `signed_key` |
| `ssh/creds/<role>` (response) | `key` |
| `ssh/verify` (request) | `otp` |

Audit logs still capture the role name, caller identity, and metadata — useful for "who signed cert serial X" investigations without exposing the cert itself.

---

## 8. Common operational recipes

### Rotate the CA

1. Generate a new CA at a *second* mount: `bvault secrets enable --path=ssh-v2 ssh; bvault write ssh-v2/config/ca generate_signing_key=true`.
2. Pin both CA pubkeys in `TrustedUserCAKeys` on target hosts (concatenate them in the file).
3. Migrate roles to the new mount.
4. Once outstanding certificates from the old CA expire (i.e. one `max_ttl` window), remove the old pubkey line from `TrustedUserCAKeys` and `bv secrets disable ssh`.

The engine has no CRL today; rotation + short TTLs are the revocation story.

### Force-command jump host

```bash
bv write ssh/roles/jump \
  key_type=ca \
  default_user=jump \
  allowed_users=jump \
  allowed_critical_options="force-command" \
  default_critical_options=force-command=/usr/local/bin/jump-shell \
  ttl=30m \
  max_ttl=4h
```

Certificates signed under this role always carry `force-command=/usr/local/bin/jump-shell`, regardless of what the caller asks for — every login lands in the jump shell.

### Source-IP restriction

```bash
bv write ssh/roles/office-only \
  key_type=ca \
  default_user=deploy \
  allowed_users=deploy \
  allowed_critical_options="source-address" \
  ttl=30m
```

Callers then pass `critical_options=source-address=203.0.113.0/24` on the sign call; if they omit it the cert has no source restriction.

### Identity-aware key id (audit trail)

Default `key_id_format` already includes `{{identity.entity.id}}`, `{{role}}`, and `{{token_display_name}}`. Tighten it if you want display name only:

```bash
bv write ssh/roles/web-admins \
  key_id_format="bv-{{identity.entity.name}}-{{role}}"
```

The cert's `key id` appears in `sshd` auth logs (`Accepted publickey for webops from … key ID "bv-felipe-web-admins"`), giving you a per-session human-readable handle.

---

## 9. GUI workflow

The desktop GUI (`SSH` page in the sidebar) wraps every endpoint above:

- **CA tab** — generate Ed25519 / ML-DSA-65, import existing OpenSSH key, copy public key, delete with confirmation.
- **Roles tab** — CRUD with a single form whose fields switch between CA and OTP modes based on `key_type`. PQC toggle (`pqc_only`) is exposed.
- **Sign Cert tab** — paste a public key, pick the role, fill in `valid_principals` / `ttl` / extensions, copy the resulting certificate.
- **OTP Creds tab** — pick role + IP + username, see the role's CIDR list, click `Lookup` to discover matching roles first, then `Mint`.

The sidebar link is visible to tokens carrying `root` or `admin` (the page is admin-only today; per-role end-user sign workflows go through the CLI / API). The page hides when no `ssh/` mount exists.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `ssh CA not configured` on `/sign` | `ssh/config/ca` has never been written. | `bv write ssh/config/ca generate_signing_key=true`. |
| `role has pqc_only=true but the CA is classical` | Role expects PQC chain, CA is Ed25519. | Either drop `pqc_only` or regenerate the CA with `algorithm=mldsa65`. |
| `ip … is not in role's cidr_list` on `/creds` | Requested target IP outside `cidr_list` or inside `exclude_cidr_list`. | Widen `cidr_list` or pick a different role. |
| `valid_principals … not allowed by role` on `/sign` | Caller asked for a principal not in `allowed_users`. | Add the principal to `allowed_users` or have the caller pick one in the list. |
| Target host rejects cert with `Certificate invalid: not yet valid` | Clock skew between client and target larger than `not_before_duration`. | Raise `not_before_duration` on the role, or sync NTP. |
| PAM `bv-ssh-helper` lookups fail silently on the target | Helper config path missing or `VAULT_ADDR` unreachable. | `tail /var/log/bv-ssh-helper.log`; confirm the helper token has `create` on `ssh/verify`. |

---

## 11. API surface summary

```
# CA mode
POST   /v1/ssh/config/ca       # generate or import the CA keypair
GET    /v1/ssh/config/ca       # read CA pubkey + algorithm
DELETE /v1/ssh/config/ca       # remove the CA
GET    /v1/ssh/public_key      # raw OpenSSH-format pubkey (audit-safe)

POST   /v1/ssh/roles/:name     # create / update role
GET    /v1/ssh/roles/:name
LIST   /v1/ssh/roles
DELETE /v1/ssh/roles/:name

POST   /v1/ssh/sign/:role      # sign a caller-supplied public key

# OTP mode
POST   /v1/ssh/creds/:role     # mint a one-time password
POST   /v1/ssh/verify          # helper-side OTP consume
POST   /v1/ssh/lookup          # which OTP roles match (ip, username)?
```

The HTTP shape is intentionally Vault-compatible — migration from HashiCorp Vault is a configuration replay.
