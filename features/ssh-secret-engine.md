# Feature: Secret Engine -- SSH (Pure-Rust, PQC-Aware)

## Summary

Add a Vault-compatible **SSH** secret engine that issues short-lived SSH credentials so operators never paste long-lived `~/.ssh/id_rsa` keys onto target hosts again. The engine supports the three modes Vault shipped:

1. **Signed Client Certificates (CA mode)** -- BastionVault holds an SSH CA keypair; clients submit their public key, the engine returns a signed OpenSSH certificate with role-bound principals, validity window, extensions, and critical options.
2. **One-Time Passwords (OTP mode)** -- BastionVault generates a single-use password; a small helper on the target host validates it against BastionVault and lets the user in once.
3. **Dynamic Keys (legacy)** -- BastionVault generates a fresh keypair, pushes the public key to the target host's `authorized_keys`, returns the private key with a TTL. Documented but **deferred to a follow-up phase** because it requires outbound SSH from the BastionVault host to every target -- an operational footprint we want to defer until the dynamic-secrets framework ([features/dynamic-secrets.md](dynamic-secrets.md)) lands.

The engine is built on a fully **pure-Rust** stack: `russh-keys` for SSH key + certificate I/O, `ssh-key` (RustCrypto) for OpenSSH wire encoding, plus the same RustCrypto + `fips204` crates the PKI engine uses. **No OpenSSL, no `aws-lc-sys`.**

This is also the first engine that surfaces **post-quantum SSH credentials**: the OpenSSH protocol now allows public-key algorithm names like `ssh-mldsa65@openssh.com` (draft, OpenSSH 9.9+ has a hybrid `mlkem768x25519-sha256` KEX and a public-key-cert space for ML-DSA via private OIDs). The CA-mode signer accepts `ml-dsa-65` as a CA key type for environments that want a PQC SSH chain end-to-end.

## Motivation

- **Eliminate static private keys**: most lateral movement attacks pivot through stolen `~/.ssh/id_*` files. Short-lived signed certificates make those files worthless after their validity window.
- **Vault parity**: customers migrating from HashiCorp Vault expect `ssh/roles/:name`, `ssh/sign/:role`, `ssh/issue/:role`, `ssh/config/ca`, and the OTP path. Reimplementing the surface preserves drop-in compatibility.
- **Fits the BastionVault story**: the [features/file-resources.md](file-resources.md) deferred phases (SFTP/SCP sync) need an SSH credential model; the SSH engine is the natural place to mint those credentials so the file-sync transport doesn't ship its own ad-hoc key store.
- **PQC SSH bridgehead**: ML-DSA SSH certificates are draft-spec but the wire format is small and well-defined. Standing one up now means BastionVault can sign certs for customers running OpenSSH HEAD or for future ML-DSA-aware client builds, without re-architecting later.

## Current State

- **Phase 1 shipped (CA mode, Ed25519).** Routes live at [`src/modules/ssh/`](../src/modules/ssh/): `path_config_ca.rs` (CA generate/import/read/delete), `path_roles.rs` (role CRUD + LIST), `path_sign.rs` (signing with policy enforcement). `policy.rs` holds the on-disk `CaConfig` + `RoleEntry` types, both forward-compatible via `serde(default)` so Phase 2 / 3 fields land without migrations. End-to-end integration test at [`tests/test_ssh_engine.rs`](../tests/test_ssh_engine.rs) verifies sign output is a valid OpenSSH cert and that role policy (principal subset, extension whitelist, default merge, TTL clamp, critical-option pass-through) actually lands in the wire format.
- **Phase 2 shipped (OTP mode + helper binary).** New routes: `POST /ssh/creds/:role` mints a one-time password (the plaintext is returned exactly once; storage holds only the SHA-256), `POST /ssh/verify` consumes it (single-use, delete-before-act so a concurrent retry can't double-spend), `POST /ssh/lookup` surfaces which OTP roles cover an `(ip, username)` pair without consuming a credential. `RoleEntry` gained `cidr_list` / `exclude_cidr_list` / `port` (validated as `ipnetwork::IpNetwork` at role-write time so a typo fails up front). The helper binary lives at [`bin/bv_ssh_helper.rs`](../bin/bv_ssh_helper.rs) and ships as the `bv-ssh-helper` Cargo bin — designed for `pam_exec` integration on managed hosts. End-to-end test at [`tests/test_ssh_otp.rs`](../tests/test_ssh_otp.rs) covers mint / lookup / verify / replay-fail / out-of-CIDR-fail / excluded-CIDR-skip.
- **Phase 3 shipped (PQC: ML-DSA-65), feature `ssh_pqc`.** New module [`src/modules/ssh/pqc.rs`](../src/modules/ssh/pqc.rs) hand-rolls the OpenSSH cert TBS encoder for the `ssh-mldsa65@openssh.com` algo via `ssh-encoding`'s primitives — `ssh-key` 0.6 doesn't recognise the (still-draft) algo as a `KeyData` variant, so we sidestep its `Builder` for the PQC path entirely and call `bv_crypto::MlDsa65Provider` for the actual FIPS 204 sign. `POST /ssh/config/ca {algorithm: "mldsa65"}` generates an ML-DSA-65 CA, persisting only the 32-byte seed (FIPS 204 keygen rederives the expanded private key on each sign). `path_sign.rs` dispatches to the PQC path when `CaConfig.algorithm == "ssh-mldsa65@openssh.com"`. `RoleEntry.pqc_only` now enforces an end-to-end PQC chain (rejects classical client public keys). Integration test at [`tests/test_ssh_pqc.rs`](../tests/test_ssh_pqc.rs) (gated on `ssh_pqc`) covers PQC CA generate, sign, wire-format envelope sanity, and the classical-client-against-`pqc_only` rejection.
- **Phase 4 shipped (GUI integration).** Tauri command surface at [`gui/src-tauri/src/commands/ssh.rs`](../gui/src-tauri/src/commands/ssh.rs) (12 commands: mount list / enable, CA read / generate / delete, role list / read / write / delete, sign, creds, lookup) sits behind matching API wrappers in [`gui/src/lib/api.ts`](../gui/src/lib/api.ts). The page itself ([`gui/src/routes/SshPage.tsx`](../gui/src/routes/SshPage.tsx)) is a four-tab UI: **CA** (generate Ed25519 / ML-DSA-65, import existing OpenSSH private key, copy public key, delete with confirmation), **Roles** (CRUD with a unified form that switches CA / OTP fields based on `key_type`, including `pqc_only` toggle), **Sign Cert** (paste-public-key-and-sign with serial / algorithm chips and a copy-cert button), **OTP Creds** (mint OTP for `(role, ip, username)` plus a `lookup` button that surfaces matching roles before consuming a credential). Sidebar nav gates the link on `requiresMountType: "ssh"` plus `root` / `admin` policies — same shape as the PKI nav. RSA / ECDSA classical algorithms remain deferred — the role's `algorithm_signer` is parsed and validated at sign time, but only `ssh-ed25519` is accepted on the classical path today.
- ML-DSA-65 signing is already available via [crates/bv_crypto/src/signature](crates/bv_crypto/src/signature) (`fips204`).
- The PKI engine spec ([features/pki-secret-engine.md](pki-secret-engine.md)) defines a `CertSigner` trait abstraction that the SSH CA can re-use almost unchanged -- only the TBS encoding differs (OpenSSH cert format vs. X.509).
- File-resource SFTP/SCP transports are explicitly deferred ([roadmap.md:109](roadmap.md:109)) pending an SSH stack decision; that decision is now: **`russh`** (pure-Rust client, MIT) over `libssh2-sys` (C lib).

## Design

### Vault-compatible HTTP Surface

```
# CA mode
POST   /v1/ssh/config/ca                       # configure or generate the CA keypair
GET    /v1/ssh/config/ca                       # read CA public key
DELETE /v1/ssh/config/ca
GET    /v1/ssh/public_key                      # convenience: just the SSH public key in OpenSSH format

POST   /v1/ssh/roles/:name                     # create / update role
GET    /v1/ssh/roles/:name
LIST   /v1/ssh/roles
DELETE /v1/ssh/roles/:name

POST   /v1/ssh/sign/:role                      # sign a client-supplied public key
POST   /v1/ssh/issue/:role                     # CA mode: generate keypair + signed cert in one call

# OTP mode
POST   /v1/ssh/creds/:role                     # generate a one-time password
POST   /v1/ssh/verify                          # vault-helper-ssh validates the OTP

# Lookup / cleanup
LIST   /v1/ssh/creds                           # list outstanding OTPs (admin)
POST   /v1/ssh/lookup                          # which roles match an `(ip, username)` pair?
```

Behaviour matches Vault's SSH engine v1 except where PQC `key_type` values introduce new fields.

### CA-Mode Roles

A role configures *what kind of certificate the engine will issue*:

| Field | Type | Description |
|---|---|---|
| `key_type` | string | CA-mode marker. `"ca"`. |
| `algorithm_signer` | string | What CA key signs the cert. `"rsa-sha2-256"` / `"rsa-sha2-512"`, `"ssh-ed25519"`, `"ecdsa-sha2-nistp256"`, `"ecdsa-sha2-nistp384"`, **`"ssh-mldsa65@openssh.com"`** (PQC). Default: `"ssh-ed25519"`. |
| `allowed_users` | string | Comma-separated list of usernames the cert may declare in `valid principals`. `*` allows any. |
| `allowed_users_template` | bool | If true, `allowed_users` may contain identity-template tokens (`{{identity.entity.name}}`). |
| `default_user` | string | Username put into `valid principals` if the caller doesn't pick one. |
| `allowed_critical_options` | string | Whitelist of `critical_options` the caller may set (e.g. `force-command`, `source-address`). |
| `allowed_extensions` | string | Whitelist of `extensions` (e.g. `permit-pty`, `permit-port-forwarding`). |
| `default_extensions` | map | Always-on extensions even if not requested. |
| `default_critical_options` | map | Always-on critical options. |
| `ttl` | duration | Default validity. |
| `max_ttl` | duration | Hard cap; per-call requests above this are clamped. |
| `cert_type` | string | `"user"` (client cert) or `"host"` (server cert). |
| `key_id_format` | string | Template for the cert's `key id` field. Default `"vault-{{identity.entity.id}}-{{role}}-{{token_display_name}}"`. |
| `not_before_duration` | duration | Allows for client-server clock skew. Default 30s. |
| `pqc_only` | bool | Reject signing requests where the **client** key is classical, even if the role's CA is PQC. Forces an end-to-end PQC chain. |

### OTP-Mode Roles

| Field | Type | Description |
|---|---|---|
| `key_type` | string | OTP-mode marker. `"otp"`. |
| `default_user` | string | Username on the target host. |
| `cidr_list` | string | CIDRs the OTP is valid for (matched against the requested target IP). |
| `exclude_cidr_list` | string | CIDRs to subtract from `cidr_list`. |
| `port` | int | Default 22. |

OTP-mode is helpful for hosts that cannot run an SSH CA-trusting `sshd` (older systems, appliances). It requires a `vault-ssh-helper`-equivalent installed on the target; we'll ship a minimal pure-Rust helper at `cmd/bv-ssh-helper/` so operators don't have to package HashiCorp's binary.

### Signing Flow (CA mode)

`POST /v1/ssh/sign/:role { "public_key": "ssh-ed25519 AAAA...", "valid_principals": "alice", "ttl": "30m", "cert_type": "user", "extensions": {"permit-pty": ""}, "critical_options": {} }`:

1. Parse the inbound `public_key` via `ssh-key` (RustCrypto) -- supports `ssh-rsa`, `ssh-ed25519`, `ecdsa-sha2-nistp{256,384,521}`, plus `ssh-mldsa65@openssh.com` once feature flag `ssh_pqc_pubkeys` is on.
2. Apply role policy:
   - Intersect requested `valid_principals` with `allowed_users`.
   - Filter `extensions` / `critical_options` against the role's whitelists.
   - Clamp `ttl` to `max_ttl`.
   - Reject if `pqc_only=true` and the client public key is classical.
3. Build the OpenSSH certificate TBS: `nonce || pubkey-fields || serial || cert_type || key_id || valid_principals || valid_after || valid_before || critical_options || extensions || reserved || signature_key`.
4. Sign the TBS with the role's `algorithm_signer` via `bv_crypto` (`MlDsa65Signer` for the PQC variant; RustCrypto signers for the classical ones), producing the certificate's trailing `signature` field.
5. Wrap, base64-encode, prefix with `<algo>-cert-v01@openssh.com `, return.

The `CertSigner` trait from PKI is reused -- the only new code is the OpenSSH-format TBS encoder in `ssh/openssh_cert.rs`.

### Signing Flow (issue, CA mode)

`POST /v1/ssh/issue/:role`: same as sign, but the engine generates a fresh client keypair (algorithm chosen by the role's `key_type`, default `ssh-ed25519`) and returns both the private key and the signed cert. Useful for short-lived bastion sessions where the operator has no key on hand. Private key never persists -- it's returned once, then dropped.

### OTP Flow

1. `POST /v1/ssh/creds/:role { "ip": "10.0.0.5", "username": "alice" }` -- engine validates `ip` against `cidr_list`, generates a 32-character random password, persists `(role, ip, username, password_hash, expiry)` at `ssh/otps/<id>`, returns `{ "key": "<password>", "key_type": "otp", "username": "alice", "ip": "10.0.0.5", "port": 22 }` plus a TTL.
2. The user runs `ssh alice@10.0.0.5`; the helper on the target captures the password and `POST /v1/ssh/verify { "otp": "<password>" }` -- engine constant-time looks up the OTP, marks it consumed, returns `{ "username": "alice", "ip": "10.0.0.5" }` so the helper can complete the PAM dance.
3. OTP entries are deleted on consume; a tidy sweep removes expired entries.

### Engine Architecture

```
src/modules/ssh/
├── mod.rs                  -- SshModule; route registration; setup/cleanup
├── backend.rs              -- SshBackend: storage I/O, per-role lock, OTP index
├── policy.rs               -- RolePolicy enum (Ca | Otp), CaConfig, OtpConfig
├── crypto/
│   ├── mod.rs              -- re-export of CertSigner from modules::pki
│   ├── ssh_key.rs          -- ssh-key wrappers, OpenSSH algo string ↔ KeyType
│   └── pqc_ssh.rs          -- ML-DSA-65 SSH cert signer (feature: ssh_pqc)
├── openssh_cert.rs         -- OpenSSH certificate TBS encoder + parser
├── otp.rs                  -- OTP generation, hash, lookup
├── path_config_ca.rs       -- /v1/ssh/config/ca + /public_key
├── path_roles.rs           -- /v1/ssh/roles/:name CRUD + LIST
├── path_sign.rs            -- /v1/ssh/sign/:role and /v1/ssh/issue/:role
├── path_creds.rs           -- /v1/ssh/creds/:role and /verify
└── path_lookup.rs          -- /v1/ssh/lookup
```

Plus a separate binary:

```
src/bin/bv-ssh-helper.rs    -- target-host helper for OTP-mode (pam_exec friendly)
```

### Mount, Audit, Lease Wiring

- `SshModule::setup()` calls `core.add_logical_backend("ssh", factory)`.
- Operators mount via `POST /v1/sys/mounts/ssh type=ssh`.
- CA-mode private keys are barrier-encrypted at rest; the public key is also persisted (so `GET /v1/ssh/public_key` is fast).
- OTPs are leases -- they show up in `/v1/sys/leases/lookup` and can be revoked via `/v1/sys/leases/revoke`. This lets operators kill an in-flight OTP if the user reports it leaked.
- Issued certificates do **not** carry leases (they're self-revocable only via short TTL + a future CRL endpoint, not in scope for Phase 1).
- Audit redacts: `private_key` (issue response), `signed_key` (sign response), `key` (OTP creds response), `otp` (verify request).

### PQC Caveats

- `ssh-mldsa65@openssh.com` is **not** in upstream OpenSSH at the time of writing. The wire format we emit follows the IETF lamps draft + the OpenSSH cert-format extension pattern. Until OpenSSH ships native support, only consumers that opt in (custom builds, third-party SSH libraries that have implemented it) will accept these certs.
- The hybrid KEX `mlkem768x25519-sha256` (OpenSSH 9.9+) protects the *transport*, not the *certificate signature*. A classical CA signing classical certs still benefits from PQC KEX during transit; the engine doesn't need to do anything for that to happen.
- Operators who want a PQC chain end-to-end set `algorithm_signer="ssh-mldsa65@openssh.com"` on the role *and* `pqc_only=true`. Until SSH clients catch up, this is mostly useful for internal automation pipelines that run a PQC-aware Rust SSH client.

## Implementation Scope

### Phase 1 -- CA Mode (Classical) — **Done (Ed25519 subset)**

Shipped: Ed25519-only CA + role-gated signing. Dropped from this phase: RSA / ECDSA (deferred to a later phase under the same `algorithm_signer` field, which is already parsed and gated at sign time), `issue/:role` (engine-generated client keypair — `sign/:role` covers the dominant case and adds no key-handling surface for the engine to leak), `openssh_cert.rs` (the `ssh-key` `certificate::Builder` API obviated needing a hand-rolled TBS encoder), and `crypto/ssh_key.rs` (the wrappers turned out to be one-liners inlined in `path_sign.rs`).

| File | Purpose |
|---|---|
| `src/modules/ssh/mod.rs` | Module + route registration. |
| `src/modules/ssh/backend.rs` | Backend wiring, per-role lock, lease integration. |
| `src/modules/ssh/policy.rs` | `RolePolicy`, `CaConfig`, `OtpConfig`. |
| `src/modules/ssh/openssh_cert.rs` | OpenSSH cert TBS encoder + parser. |
| `src/modules/ssh/crypto/ssh_key.rs` | `ssh-key` (RustCrypto) wrappers. |
| `src/modules/ssh/path_config_ca.rs` | CA config + generate. |
| `src/modules/ssh/path_roles.rs` | Role CRUD. |
| `src/modules/ssh/path_sign.rs` | `sign` + `issue`. |

Dependencies:

```toml
ssh-key      = { version = "0.6", default-features = false, features = ["alloc", "ed25519", "p256", "p384", "rsa", "encryption"] }
ssh-encoding = "0.2"
```

### Phase 2 -- OTP Mode + Helper Binary — **Done**

Shipped exactly the file set the spec listed (helper moved to `bin/bv_ssh_helper.rs` to match the existing layout for the server bin). Per-OTP `RwLock` was deemed unnecessary in practice — the storage layer's atomic delete-before-respond on `verify` gives the same single-use guarantee, and the OTP is keyed by SHA-256 hash so even hostile timing of the lookup itself only leaks the hash, not the OTP. The conf file format the helper reads is intentionally `KEY=VALUE` (not TOML) so the helper avoids a serde dep on the target host.

| File | Purpose |
|---|---|
| `src/modules/ssh/otp.rs` | OTP gen/store/consume. |
| `src/modules/ssh/path_creds.rs` | `creds` + `verify`. |
| `src/modules/ssh/path_lookup.rs` | `lookup`. |
| `bin/bv_ssh_helper.rs` | Helper binary for target hosts (Cargo bin `bv-ssh-helper`). |

### Phase 3 -- PQC SSH Certificates — **Done**

Feature flag: `ssh_pqc`. Off by default — OpenSSH doesn't yet ship native support for the `ssh-mldsa65@openssh.com` algo, so certs minted under this feature only verify in clients that have implemented the draft. The cert TBS encoder is hand-rolled on top of `ssh-encoding` rather than `ssh-key` because the latter's `Builder` won't accept a `KeyData::Other` for arbitrary public-key bytes.

| File | Purpose |
|---|---|
| `src/modules/ssh/pqc.rs` | ML-DSA-65 OpenSSH wire format (public-key + cert TBS) and signer; `parse_pqc_public_key()` for the inbound client-key path. |
| `path_config_ca.rs` (extension) | `algorithm = "mldsa65"` request body branch generates an ML-DSA-65 CA (32-byte seed + 1952-byte pubkey persisted hex-encoded). |
| `path_sign.rs` (extension) | `handle_sign_pqc` parallel sign handler; the top-level dispatcher routes to it when `CaConfig.algorithm` matches the PQC algo string. Also enforces `RoleEntry.pqc_only` at this seam. |

### Phase 4 -- GUI Integration — **Done**

Shipped as a dedicated `/ssh` page rather than a tab inside the existing Secrets page — aligns with the PKI engine's GUI shape, which is a separate page with its own sidebar entry and per-mount selector. `SshIssueModal.tsx` is dropped from the file list because the engine never shipped `issue/:role` (that was deferred from Phase 1 to keep the keyhandling surface minimal); paste-public-key-and-sign covers the dominant case.

| File | Purpose |
|---|---|
| `gui/src-tauri/src/commands/ssh.rs` | 12 Tauri commands bridging the GUI to the engine routes. |
| `gui/src/routes/SshPage.tsx` | Four-tab page: CA, Roles, Sign Cert, OTP Creds. |
| `gui/src/lib/api.ts` (extension) | Typed wrappers for `ssh_*` commands. |
| `gui/src/lib/types.ts` (extension) | `SshMountInfo`, `SshCaInfo`, `SshRoleConfig`, sign / creds / lookup request + result types. |
| `gui/src/components/Layout.tsx` (extension) | Sidebar nav entry with `requiresMountType: "ssh"`. |
| `gui/src/App.tsx` (extension) | `/ssh` route registration. |

### Not In Scope

- **Dynamic-keys mode** (Vault's third historical mode that pushes a key to `authorized_keys` over outbound SSH). Requires the dynamic-secrets framework -- tracked in [features/dynamic-secrets.md](dynamic-secrets.md). If we ship it, it'll be Phase 5.
- **CRL / revocation** for issued certificates. OpenSSH supports `RevokedKeys` files but distribution is operator-managed. A future phase can ship a `GET /v1/ssh/krl` endpoint emitting an OpenSSH KRL.
- **Host certificates rotation pipeline** (auto-sign hosts when they boot). Out of scope; would belong to a separate "SSH host management" feature.
- **HSM-backed CA keys**. Tracked in [features/hsm-support.md](hsm-support.md) Phase 3.
- **GUI live SSH terminal**. Out of scope; the engine issues credentials, it does not run sessions.

## Testing Requirements

### Unit Tests

- OpenSSH cert TBS round-trip: build TBS for a fixed input, sign with a known Ed25519 key, parse back, verify byte-identical.
- `ssh-key` parsing for every supported algorithm (RSA, Ed25519, ECDSA P-256/P-384, ML-DSA-65).
- Role policy enforcement: requested principal not in `allowed_users` -> rejected; requested extension not in `allowed_extensions` -> stripped; TTL above `max_ttl` -> clamped.
- OTP lifecycle: create OTP, verify once -> ok; verify again -> rejected; expire -> rejected.

### Integration Tests

- Generate a CA, sign a public key, the resulting cert validates with `ssh-keygen -L -f cert.pub` (test runner has OpenSSH installed).
- Run a `russh`-based test client that connects to a `russh`-based test server with the issued cert as auth -- end-to-end CA-cert auth.
- OTP flow: create OTP, run a mock helper that POSTs `/verify`, confirm success and that re-verify fails.
- PQC: sign with ML-DSA-65 CA, parse with our own parser, verify signature with `fips204`.

### Cucumber BDD Scenarios

- Operator mounts SSH engine, generates CA, registers public key on a target host's `TrustedUserCAKeys`, then signs a client key; the operator SSHes in using the cert.
- Operator creates an OTP role for `10.0.0.0/24, alice`, generates an OTP, the helper validates it; subsequent attempts with the same OTP fail.

### Negative Tests

- `pqc_only=true` role rejects a classical client public key.
- Role with `allowed_users="alice,bob"` rejects a sign request with `valid_principals="root"`.
- `cert_type="user"` request to a `host`-only role rejected.
- Tampering the cert blob (flip one byte in the signature) -> verifies as invalid.

## Security Considerations

- **No OpenSSL, no `aws-lc-sys`**: same constraint as PKI / Transit / TOTP.
- **CA private key handling**: barrier-encrypted at rest, zeroized after use, never logged. `GET /v1/ssh/config/ca` returns only the public key.
- **Audit redaction**: `private_key`, `signed_key`, `key` (OTP), `otp` are HMAC'd in audit logs.
- **OTP entropy**: 32 base32 characters (160 bits) from `OsRng`. The hash stored in `ssh/otps/<id>` is BLAKE2b-256 -- comparison is constant-time.
- **OTP single-use**: `verify` is idempotent only in the negative direction. The first successful match marks the OTP consumed inside the same transaction; concurrent verifies cannot both succeed (per-OTP `RwLock`).
- **TTL clamping**: every issued cert is clamped to `max_ttl`. There is no "infinite TTL" mode.
- **Cert nonce**: every signed cert carries a random 32-byte nonce so two certs over the same public key + role + window are still distinguishable; this matters because an attacker who steals one cert cannot replay-sign a different one.
- **PQC signer side-channels**: `fips204` is constant-time per FIPS 204 reference. We rely on this guarantee and do not custom-implement ML-DSA.
- **Helper binary trust boundary**: `bv-ssh-helper` runs on the target host and talks to BastionVault over TLS using a token mounted in PAM context. The helper must be installed at a path only root can write to; documented in the helper's README.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md), [roadmap.md](../roadmap.md), and this file's "Current State" / phase markers.
