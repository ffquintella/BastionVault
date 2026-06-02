# Connect-Only Access

**Status:** Phase 1 (backend) + Phase 2a (GUI filtering) + Phase 2b (GUI
Rustion credential-reference connect path) done.

## Goal

Allow an operator to be granted the ability to **open a brokered session to a
resource through Rustion without being able to read that resource's stored
credentials/secrets**. The credential is resolved server-side and injected by
the bastion; the connect-only operator never sees it. The GUI reflects the
policy by hiding credential values and restricting connections to
Rustion-brokered profiles.

## Model

A new ACL capability, **`connect`** (`Capability::Connect = 1 << 9` in
`src/modules/policy/policy.rs`), parsed from HCL like any other capability:

```hcl
path "resources/secrets/db-prod/*" {
  capabilities = ["connect"]      # may open a session, may NOT read the secret
}
```

`read` (and `root`) imply `connect`, so existing `read`+everything users are
unaffected. `connect` alone grants neither read nor list of the credential.

## How it works

| Concern | Mechanism |
|---------|-----------|
| Capability | `Connect` added to the `Capability` enum/bitmap; flows through strum/serde/HCL and `to_granting_capabilities` automatically. |
| Session-open gate | `rustion/v2/session/open` (`handle_session_open_v2`, `src/modules/rustion/mod.rs`) runs a **secondary ACL check** — `ACL::capabilities("resources/secrets/<name>/")` must include `connect`/`read`/`root` — before resolving any credential. Distinct from the `Write` gate `post_auth` runs on the endpoint path itself. |
| Server-side resolution | When the caller passes a credential **reference** (`credential_source = {kind:"secret", secret_id:"…"}`) instead of raw `credential_material`, the handler reads `resources/secrets/<name>/<key>` via `core.router.handle_request` (server authority, bypasses the caller's ACL) and brokers it. The connect-only caller never reads it. Only the `ssh-password` shape is brokered server-side today — matching the bastion proxy's current capability. |
| Audit | The server-side read emits a `target: "security"` log line (`rustion-connect-resolve: user=… resource=… key=…`) attributed to the connecting operator. |
| GUI capability lookup | `v2/sys/capabilities-self` (`handle_capabilities_self`, `src/modules/system/mod.rs`; HTTP shim `/v2/sys/capabilities-self`, v2-only) returns the caller's effective capabilities per path. Vault-compatible shape. |
| GUI filtering | The Resources page queries capabilities for `resources/secrets/<name>/`; when the caller has `connect` but not `read`, it hides credential values (`ResourceSecretsPanel`) and restricts launchable connection profiles to `kind: "rustion"` (`ConnectionProfilesPanel`). |

## Phases

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | `connect` capability; secondary connect gate + `rustion/v2/session/open` with server-side `secret`-kind resolution; `v2/sys/capabilities-self`. Unit + integration tests. | **Done** |
| 2a | GUI: `capabilities_self` Tauri command + `api.capabilitiesSelf`; hide credentials + restrict to Rustion profiles for connect-only users; connect-only notices. | **Done** |
| 2b | GUI: the SSH Rustion connect path sends a credential reference to `rustion/v2/session/open` for `secret`-backed profiles (no client-side read). See below. | **Done** |
| Deferred | RDP Rustion connect path (`session_open_rdp`) — same rewiring once the bastion supports rdp-password server-side resolution. Server-side resolution for `ldap` / `ssh-engine` / `pki` kinds (those use the operator's own typed creds or mint ephemeral certs — not the stored secret connect-only protects). | Not started |

### Phase 2b — GUI Rustion connect path (done)

`gui/src-tauri/src/commands/connect.rs`: `session_open_ssh` now, for
`credential_source.kind == "secret"`, calls `open_rustion_session_v2_ssh`
first. That helper reads the effective policy and — when it routes through a
bastion — POSTs a credential **reference** (`resource_name` +
`credential_source`) to `rustion/v2/session/open`, so BastionVault resolves
the secret server-side. The GUI never reads the credential, so a connect-only
operator can launch. It returns `Direct` when the policy doesn't route through
a bastion, and the caller falls back to the existing client-side resolution
path (used for direct dials and `ldap`/`ssh-engine`/`pki` kinds). The v1 and
v2 paths share `parse_rustion_ticket_bundle`, so the downstream SSH dial is
identical. RDP is deferred (the bastion's rdp-password server-side path is not
wired yet).

## Tests

- `src/modules/policy/policy.rs` — `connect` round-trips (string/bit/HCL),
  connect-only grant does not imply read.
- `src/modules/policy/acl.rs` — `ACL::capabilities` returns `connect` (not
  `read`) for a connect-only policy; both for read+connect.
- `src/modules/system/mod.rs` — `v2/sys/capabilities-self` returns `connect`
  without `read` for a connect-only userpass token, and both for read+connect.
- `src/modules/rustion/mod.rs` (`connect_only_tests`) — **end-to-end through
  the real HTTP + core pipeline:** a connect-only token is denied a direct
  read of the resource secret (403) but its `rustion/v2/session/open` passes
  the connect gate and resolves the credential server-side, reaching dispatch
  (502/503 with no bastion enrolled — not a gate 403); a no-connect token is
  denied at the gate (403). This exercises the entire new server-side path
  (gate + router-direct secret read + dispatch) without a live bastion.

### On the full bastion e2e

The actual SSH proxying through a bastion is byte-identical to the existing v1
`rustion/session/open` flow — `handle_session_open_v2` resolves the credential
and then feeds the **same** envelope/dispatch path with the same
`credential_material` bytes. The only new behavior is *where* the credential
is resolved (server vs client), which the deterministic test above covers.

The Docker bastion harness at `tests/e2e/rustion-ssh/` had **rotted since
v0.7** across both repos; it is now **revived and exercises connect-only
through a live bastion end-to-end**. Fixes (see `tests/e2e/rustion-ssh/run.sh`):

- BV `Dockerfile` `COPY plugins-ext` (workspace-excluded + `.dockerignore`d) →
  removed; the dead `BASTION_VAULT_LOCAL_DEV` env (read by no code) → removed.
- Rustion build context `../../../Rustion` (nonexistent) → the sibling
  `../../../../rustion`; obsolete compose `version:` key dropped.
- `run.sh` now drives init+unseal over the API (no auto-init env var), so
  `docker compose up -d` + `run.sh` works from a cold, sealed start.
- Rustion `rustion.toml` rewritten to the current
  `rustion_core::config::RustionConfig` schema (the old `[audit]
  checkpoint_interval_secs`, `[recording] root_dir/format`, `[ssh]
  allow_bv_ticket`, `identity_pub/priv` keys were renamed/removed); `run.sh`
  also mints the control-plane TLS cert (validation requires it) and seeds a
  cert-auth-only admin user so the TTY-less container doesn't block on the
  first-run password prompt.
- Enrolment is fully automated: BV's master pubkey (PEM body = base64 raw key)
  is pinned as a Rustion authority in the `authority_disk::AuthorityYaml`
  schema (`pubkey_ed25519_b64` / `pubkey_mldsa65_b64`); the bastion is enrolled
  on BV with rustion's ML-KEM-768 pubkey (from the bind-mounted `identity.pub`)
  and its Ed25519+ML-DSA-65 signing pubkeys (from `rustion control-plane
  webhook-key export`), with rustion's self-signed control-plane leaf pinned so
  BV's strict-TLS client accepts it.

The driver then proves the contract live: the target is probed `up`, a
connect-only token is **denied a direct read** of the resource secret (403),
yet its `rustion/v2/session/open` resolves the `ssh-password` credential
server-side and proxies a **real SSH shell** through the bastion to the OpenSSH
target (`id -un` → the target's `deploy` user) — the operator never reads the
credential. The bastion consumes the BV ticket in the SSH password slot
(`tkt_…`, source-IP bound), identical to the v1 proxy path.

## Operator note

A policy granting `connect` on a resource's secret path must also grant the
caller `Write` (create/update) on the rustion mount path used by
`rustion/v2/session/open` (e.g. `path "rustion/*" { capabilities = ["update"] }`),
same as any other Rustion session-open caller.
