# Feature: Connect-time MFA re-validation + FIDO2 security-key SSH login

## Summary

Two related additions to Resource Connect ([features/resource-connect.md](resource-connect.md)):

1. **Per-profile MFA re-validation gate.** A connection profile can be marked
   `require_mfa`. Opening a session with that profile requires the connecting
   operator to re-prove a second factor — a TOTP code or a FIDO2 security key —
   *immediately before* the session opens. The decision and the verification are
   both server-side; the client cannot assert its way past the gate.

2. **`fido2` credential source (SSH).** The operator's FIDO2 security key becomes
   the SSH authentication method itself, using an OpenSSH `sk-ssh-ed25519@openssh.com`
   (or `sk-ecdsa-sha2-nistp256@openssh.com`) key whose private half never leaves the
   authenticator. Every connect requires a physical touch.

The two compose: a `fido2`-source SSH profile with `require_mfa` set asks for the
key twice — once for the vault-side step-up, once for the SSH signature — because
they prove different things to different verifiers.

## Motivation

- **A vault token is a bearer token.** Once an operator has authenticated in the
  morning, everything their policies allow is reachable for the life of that token,
  including production RDP. Regulated environments (PCI-DSS 8.3, NIST 800-53 IA-2)
  want a fresh factor at the moment of privileged access, not just at login. The
  gate makes "re-prove yourself to open *this* session" a per-profile property.
- **Static SSH keys on operator laptops are the last unmanaged credential.** The
  SSH engine already removes shared static keys from the vault side, but an
  operator's own key still sits on disk. An `sk-` key moves the private half into
  a hardware authenticator: unexportable, non-cloneable (signature counter), and
  unusable without a touch. Phishing and host-compromise both stop working.
- **We already ship both halves.** The vault is a WebAuthn relying party
  (`src/modules/credential/fido2/rp/`), the desktop client already drives USB
  authenticators natively over CTAP2 (`gui/src-tauri/src/commands/fido2_native.rs`),
  and `russh` already advertises the `sk-` algorithms and knows the PROTOCOL.u2f
  signature encoding. This feature wires existing parts together rather than
  introducing new cryptography.

## Current State

- Connection profiles carry `credential_source` ∈ {`secret`, `ldap`, `ssh-engine`,
  `pki`, `default-account`}, stored as opaque JSON on the resource record's
  `connection_profiles` array. Nothing on a profile can require a second factor.
- TOTP MFA exists but only as a *login* second factor for userpass
  (`user.totp_mfa_enabled`, checked in `path_login.rs`), gated by a global
  `TotpMfaConfig.enabled`. There is no way to re-prove a factor mid-session.
- FIDO2 exists as a login method (`auth/userpass/fido2/login/{begin,complete}`)
  which mints a token. There is no verify-only ceremony.
- The desktop client's CTAP2 bridge is hardwired to the WebAuthn login ceremony
  (`rp_id` = the vault's relying-party id, `clientDataJSON` = WebAuthn-shaped).
- `russh` 0.61 exposes `authenticate_publickey_with` + the `auth::Signer` trait, and
  its agent client already encodes `sk-` signatures — but nothing in-tree implements
  a non-agent `Signer`.

## Scope

### In scope

- **`require_mfa: boolean`** on `ConnectionProfile`, editable per profile, for both
  SSH and RDP and every credential source.
- **Verify-only step-up ceremony on the userpass backend** —
  `auth/userpass/v2/step-up/{begin,verify}`. Authenticated callers only; the
  username is always taken from the caller's own token, never from the request
  body. Verifies a TOTP code or a FIDO2 assertion and returns `{verified}`. Mints
  no token and creates no lease.
- **Connect-MFA ticket** — `resources/v2/connect/mfa/{begin,verify}`. `begin`
  reads the profile server-side and reports whether MFA is required and which
  factors the caller actually has; `verify` runs the step-up and, on success,
  mints a single-use ticket bound to (principal, namespace, resource, profile)
  with a 120-second TTL.
- **Enforcement**:
  - `rustion/v2/session/open` (the brokered path — all credential sources, SSH
    and RDP) refuses to build an envelope without a valid ticket.
  - `resources/v2/connect/authorize` — the direct path's pre-flight. Consumes
    the ticket, emits the audit line, and returns the authorization the Tauri
    host requires before it opens a session window.
- **`fido2` credential source** for SSH profiles: the connecting operator's
  enrolled security key authenticates the session.
- **Per-principal SSH security-key enrollment** —
  `sys/v2/identity/ssh-security-key/{self,{mount}/{name}}`, storing the OpenSSH
  public key, the CTAP credential id, and the application string. Mirrors the
  storage and route shape of the default-resource-account store.
- **Native CTAP2 SSH signer** in the Tauri host: a `russh::auth::Signer` that
  drives `getAssertion` with `rpId` = the SSH application string and
  `clientDataHash` = `SHA-256(ssh_to_sign)`, then emits the PROTOCOL.u2f
  signature blob.
- **GUI**: the profile-editor toggle, a connect-time MFA prompt, the enrollment
  flow, and the `fido2` source in the credential-source picker.

### Out of scope (explicit)

- **FIDO2 as an RDP authentication method.** RDP has no FIDO2 auth mechanism;
  its strong-auth story is smartcard/PKINIT, which the `pki` credential source
  already covers. The `fido2` source is refused on RDP profiles at save time and
  at connect time. RDP profiles get the MFA *gate*, not the credential source.
- **Resident/discoverable `sk-` keys.** v1 enrolls a non-discoverable credential
  and stores the credential id server-side. Discoverable keys would let an
  operator connect from a machine with no enrollment record, at the cost of a
  credential-management round trip on every authenticator; deferred.
- **`sk-` keys via a system ssh-agent.** Considered and rejected for v1 — see
  "Notes on alternatives considered".
- **`verify-required` / PIN-enforcing `sk-` keys.** The OpenSSH `sk-` format has a
  `no-touch-required` flag and a UV variant; v1 always requires touch and treats
  user verification as `preferred`.
- **Step-up for non-userpass principals.** AppRole, certificate, and OIDC
  principals have no TOTP/FIDO2 factor on file. A gated profile fails closed for
  them with an explicit error rather than silently passing.
- **Per-profile choice of *which* factor.** `require_mfa` accepts any factor the
  operator has enrolled. Pinning "FIDO2 only" is a plausible follow-on.

## Design

### Profile shape

```ts
export interface ConnectionProfile {
  // …existing fields…
  /** Require the connecting operator to re-prove a second factor
   *  (TOTP or FIDO2) immediately before the session opens. */
  require_mfa?: boolean;
  credential_source: CredentialSource;   // now includes { kind: "fido2" }
}
```

Both are optional and default to off/absent, so every profile written before this
change keeps its exact behaviour.

### The ticket

A ticket is 32 bytes from the CSPRNG, base64url-encoded. Only `SHA-256(ticket)` is
persisted, at the barrier root under `connect/mfa-tickets/<hex>`:

```rust
struct ConnectMfaTicket {
    mount: String,        // "userpass/"
    principal: String,    // "alice"
    namespace: String,    // caller's namespace path ("" = root)
    resource: String,     // canonical (lowercase) resource name
    profile_id: String,
    method: String,       // "totp" | "fido2" — recorded for the audit line
    issued_at: String,
    expires_at: String,
}
```

Barrier root (not the resource mount's view) because the brokered path enforces
from the `rustion/` mount and the direct path from `resources/` — the same record
has to be readable from both, exactly like the default-resource-account store.

Consumption is **delete-then-validate**: the guard removes the record before it
decides, so a replay of the same ticket loses the race rather than winning it. The
binding check covers principal, namespace, resource, and profile id; the expiry
check is independent of the storage TTL.

### Endpoints

| Path | Op | Purpose |
|---|---|---|
| `auth/userpass/v2/step-up/begin` | Write | Which factors the *calling* user has; FIDO2 assertion challenge |
| `auth/userpass/v2/step-up/verify` | Write | Verify TOTP code / FIDO2 assertion for the calling user. `{verified: true}` |
| `resources/v2/connect/mfa/begin` | Write | `{resource, profile_id}` → `{required, methods, fido2?}` |
| `resources/v2/connect/mfa/verify` | Write | `{resource, profile_id, method, totp_code?/credential?}` → `{ticket, expires_at}` |
| `resources/v2/connect/authorize` | Write | `{resource, profile_id, connect_ticket?}` → consume the ticket, audit, `{authorized}` |
| `sys/v2/identity/ssh-security-key` | List | Principals with an enrolled SSH security key |
| `sys/v2/identity/ssh-security-key/self` | Read/Write/Delete | The calling operator's own enrollment |
| `sys/v2/identity/ssh-security-key/{mount}/{name}` | Read/Write/Delete | Admin view of one principal's enrollment |

`rustion/v2/session/open` gains two optional request fields, `profile_id` and
`connect_ticket`. When the named profile carries `require_mfa`, both are mandatory
and the ticket is consumed before the dispatcher runs.

### Why the gate cannot be bypassed — and where it stops

The `require_mfa` flag lives on the resource record, which the caller can only
change through the resource module's own ACL-gated write path. The server reads the
flag itself on every connect; it never trusts a client-supplied "MFA was done"
claim. The factor ceremony runs inside the vault against the caller's own token.

The gate is **absolute** on the brokered path: no ticket, no envelope, no session.
A connect-only operator (`connect` but not `read` on `resources/secrets/<name>/`)
has no other route to the credential at all, so for them the gate is absolute
full stop.

On the **direct** path with an operator who holds `read` on the secret, the gate
is an **audited workflow control, not a containment boundary**. Such an operator
can read the credential out of the vault and dial the target with their own SSH
client — with or without this feature. That is a property of granting `read`, and
this feature neither creates nor closes it.

We deliberately did **not** add a server-side "resolve this profile's credential
for me" endpoint to close the direct-path gap. It would have made the gate look
airtight while handing a connect-only operator the very plaintext credential that
connect-only access exists to withhold — a strictly worse security posture bought
with a better-sounding guarantee.

So: pair `require_mfa` with connect-only access
([features/connect-only-access.md](connect-only-access.md)) or with the brokered
Rustion path when you need a hard control. On a direct-path profile whose operator
can read the secret, it is a prompt and an audit record. The profile editor says
exactly this inline, so nobody has to read this file to find out.

### `sk-` key enrollment

Registration runs entirely in the Tauri host over CTAP2:

1. `makeCredential` with `rp.id = "ssh:"` (the OpenSSH application default),
   `pubKeyCredParams = [Ed25519(-8), ES256(-7)]`, `residentKey = discouraged`,
   `userVerification = preferred`, `clientDataHash = SHA-256(challenge)`.
2. The attestation object yields the credential id and the COSE public key.
3. The host derives the OpenSSH public key:
   `string "sk-ssh-ed25519@openssh.com" || string pubkey(32) || string application`
   (or the nistp256 variant: `… || string curve || string point(65) || string application`).
4. `POST sys/v2/identity/ssh-security-key/self` stores
   `{algorithm, public_key (authorized_keys line), credential_id_b64url, application}`.

Nothing secret is stored: the record holds a public key and a credential handle.
The operator installs the same `public_key` line in the target's
`~/.ssh/authorized_keys`, exactly as they would for any other key.

### `sk-` signing at connect time

`authenticate_publickey_with(user, sk_public_key, None, &mut signer)` hands the
signer the buffer russh built for `SSH_MSG_USERAUTH_REQUEST`. The signer:

1. `client_data_hash = SHA-256(to_sign)` — the SSH signed data takes the place of
   WebAuthn's `clientDataJSON` hash, per PROTOCOL.u2f.
2. `getAssertion` with `rpId = application`, `allowList = [credential_id]`,
   `userPresence = true`. The operator touches the key.
3. Parse `authData`: `rpIdHash(32) || flags(1) || counter(4)`. Reject anything
   longer — an extensions block would make the target's reconstruction of the
   signed message differ, and the signature would silently fail to verify.
4. Append to the to-sign buffer:
   ```text
   uint32  len(alg) + len(sig) + 8 + 5
   string  alg          "sk-ssh-ed25519@openssh.com"
   string  sig          64 raw bytes (or the ECDSA r||s DER→(r,s) pair)
   byte    flags
   uint32  counter
   ```
   which is byte-identical to what `russh`'s agent client emits for `sk-` keys.

The 30-second CTAP timeout is deliberately shorter than the SSH banner timeout so
a missing touch surfaces as "no touch registered on the security key" rather than
as an opaque connection reset.

### Module / file layout

| File | Role |
|---|---|
| `src/modules/credential/userpass/path_step_up.rs` | Verify-only TOTP / FIDO2 ceremony for the calling user |
| `src/modules/totp/mfa.rs` | Shared TOTP-code verification (extracted from `path_login.rs`) |
| `src/modules/resource/connect_mfa.rs` | Ticket store, `connect/mfa/*` handlers, `require_connect_mfa` guard |
| `src/modules/identity/ssh_security_key.rs` | Per-principal `sk-` enrollment store |
| `gui/src-tauri/src/session/sk_signer.rs` | CTAP2-backed `russh::auth::Signer` |
| `gui/src-tauri/src/commands/connect_mfa.rs` | Step-up ceremony driver (TOTP prompt / CTAP2 assertion) |
| `gui/src-tauri/src/commands/ssh_security_key.rs` | Enrollment (CTAP2 `makeCredential` → OpenSSH public key) |
| `gui/src/components/ConnectMfaPrompt.tsx` | Connect-time factor prompt |

## Phases

### Phase 1 — Server: step-up ceremony + ticket + enforcement — **Done**

`path_step_up.rs`, `totp/mfa.rs`, `connect_mfa.rs`, the `rustion/v2/session/open`
check, and `resources/v2/connect/authorize`.

### Phase 2 — Server: `sk-` enrollment store + sys routes — **Done**

`identity/ssh_security_key.rs`, the `sys/v2/identity/ssh-security-key/*` logical
routes, and the `src/http/sys.rs` HTTP wiring.

### Phase 3 — Host: CTAP2 signer + `fido2` credential source — **Done**

`sk_signer.rs`, `SshCredential::SecurityKey`, the `fido2` resolver in
`commands/connect.rs`, and enrollment in `commands/ssh_security_key.rs`.

### Phase 4 — Host + GUI: the MFA gate on both connect paths — **Done**

`commands/connect_mfa.rs`, the gate in `session_open_ssh` / `session_open_rdp`,
the profile-editor toggle, and `ConnectMfaPrompt`.

### Phase 5 — Deferred

Resident `sk-` keys, per-profile factor pinning, `sk-` keys through the Rustion
bastion (the bastion's russh client would need the same signer, and the
authenticator is on the operator's desk, not the bastion's), and step-up for
non-userpass principals.

## Security Considerations

- **The ticket is a bearer artifact.** It is single-use, expires in 120 seconds,
  is bound to one (principal, namespace, resource, profile) tuple, and only its
  SHA-256 is persisted. A stolen ticket is useful only against the exact profile
  it was minted for, within two minutes, and only if the thief wins the race
  against the legitimate connect.
- **Delete-before-validate.** The guard deletes the ticket record before checking
  its contents, so two concurrent redemptions cannot both succeed.
- **No oracle on the step-up path.** `verify` returns `{verified: true}` or an
  error; it never reveals whether a factor exists for another principal, because
  it only ever operates on the caller's own token identity.
- **The signature counter still matters.** The step-up FIDO2 path writes the
  authenticator's new sign count back to the user record, so clone detection keeps
  working across login and step-up alike.
- **`sk-` private keys never exist in the vault, the host, or the GUI.** The
  enrollment record holds a public key and a credential handle. Compromising the
  vault yields no ability to authenticate as the operator.
- **`authData` is length-checked.** A signature over an `authData` carrying an
  extensions block would not verify against the target's reconstruction; the
  signer rejects it explicitly rather than emitting a signature that fails
  confusingly at the far end.
- **Failure is closed.** No enrolled factor + `require_mfa` ⇒ the connect is
  refused with an explicit error. No enrolled `sk-` key + `fido2` source ⇒ the
  same. There is no fallback to a weaker path.
- **Residual risk** on the direct path with `read` on the secret — see "Why the
  gate cannot be bypassed — and where it stops" above.

## Testing Plan

### Unit tests

- Ticket store: mint → consume succeeds; second consume fails; wrong resource,
  wrong profile, wrong principal, wrong namespace each fail; expired fails.
- `require_mfa` false ⇒ no ticket demanded; `require_mfa` true with no ticket ⇒
  permission denied.
- TOTP step-up accepts a code inside the skew window and rejects one outside it.
- `sk-` signature blob encoding matches the byte layout `russh`'s agent client
  produces for the same inputs.
- OpenSSH public-key derivation from a COSE Ed25519 key round-trips through
  `ssh_key::PublicKey::from_openssh`.
- Profile validation rejects `fido2` on RDP profiles.

### Integration tests

- `rustion/v2/session/open` against a gated profile: refused without a ticket,
  accepted with one, refused on ticket reuse.
- `resources/v2/connect/authorize` refuses without a ticket on a gated profile,
  passes on an ungated one, and burns the ticket on the first call.

## Tracking

- [CHANGELOG.md](../CHANGELOG.md) — `[Unreleased]`
- [roadmap.md](../roadmap.md)
- [features/resource-connect.md](resource-connect.md) — credential-source matrix

## Notes on alternatives considered

- **`sk-` keys through the system ssh-agent.** `russh` already implements `Signer`
  for its agent client, so this would have been nearly free. Rejected because it
  moves the key policy outside BastionVault: the agent decides what is loaded and
  whether a touch is required, the operator must have an agent running with the
  right key, and there is nothing for the vault to enroll, audit, or revoke. The
  native path keeps the enrollment record — and therefore the audit trail and the
  admin revoke — inside the product.
- **Gating the raw `resources/secrets/<name>/<key>` read on the profile flag.**
  Simple, and genuinely unbypassable — but it would break the Secrets tab for
  every operator on any resource that happens to carry one gated profile, since
  a secret read carries no profile context. Rejected as an unacceptable blast
  radius for the gain.
- **A server-authority `connect/credential` resolver for the direct path.** This
  would have made the direct-path gate unbypassable *for the `secret` source* by
  routing the resolution through the server behind the ticket check. Rejected
  because the endpoint would return the plaintext credential to its caller, and
  the caller it exists to serve is precisely the connect-only operator who is
  supposed never to see it. Closing a workflow gap by opening a credential-
  disclosure hole is a bad trade, and the "hard control" label it would have
  earned was the dangerous part.
- **Reusing `auth/userpass/fido2/login/complete` for the step-up.** It already
  performs exactly the right assertion ceremony, but it mints a token and a lease
  as a side effect. A step-up must not manufacture new credentials.
- **A long-lived "MFA satisfied" claim stamped on the token.** Cheaper (one
  ceremony per hour rather than per connect) but it converts a per-session control
  into a per-session-*window* one, which is precisely what the feature exists to
  avoid.
