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

`connect` is also a **share** capability, grantable per (target, grantee) like
`read`/`list`/`update`/`delete`/`create`:

```
PUT identity/sharing/by-target/resource/<b64>/<entity>
    { "capabilities": "connect" }   # may open a session, may NOT read the secret
```

The implication above does **not** cross into sharing: a share carrying only
`read` conveys no session. Policy grants are admin-authored and `read` there
already means "may take the credential and dial it by hand", so withholding
`connect` would be theatre. A share is user-authored delegation, where "may
see this credential" and "may open sessions as it" are two decisions the
grantor makes separately — and if `read` implied `connect`, the connect-only
shape this feature exists to provide would be inexpressible as a share.
Ownership is unaffected: an owner connects to their own resource with no share
in play.

## How it works

| Concern | Mechanism |
|---------|-----------|
| Capability | `Connect` added to the `Capability` enum/bitmap; flows through strum/serde/HCL and `to_granting_capabilities` automatically. |
| Connect gate | **One** implementation, `PolicyStore::may_connect_target`, called by every gate: both rustion open routes (`may_connect_resource`, `src/modules/rustion/mod.rs`) and the resource mount's `require_connect_grant` (`src/modules/resource/connect_mfa.rs`, which fronts `connect/mfa/{begin,verify}` and `connect/authorize`). Distinct from the `Write` gate `post_auth` runs on the endpoint path itself. Three ways to pass, in cost order: an **explicit ungated** `connect` grant on `<ns>/resources/secrets/<name>/`, an ungated `read` grant, or **ownership / a share carrying `connect`**. The first two are probed with `ACL::explain_capability`, which fails scope-gated rules closed so the share-scoped baseline can't read as a blanket grant; the third with `ACL::explain_capability_for_request` over a probe carrying the owner / share / asset-group qualifiers the real pipeline resolves, plus `share_capability_override = "connect"` so the share must say `connect` rather than `read`. It is deliberately one function: it was two, and the resource-mount copy — which *documented itself as identical* — was missing the third arm entirely, so a share-grantee was refused at `connect/mfa/begin` while `session/open` accepted them. |
| Endpoint-level grants | The three `resources/v2/connect/*` endpoints are fixed paths, not per-object ones, so the pipeline's ACL check guards *who may call them*, not *which resource they name in the body* — each handler re-authorizes that through the connect gate above. Both baselines therefore grant them `update`: `default` bare, `namespace-shared` `{{namespace.path}}`-templated (`resources/` is namespace-rewritten; `rustion/` is not, which is why its grants sit bare in `namespace-self`). Ungranted, the GUI's unconditional `mfa/begin` pre-flight — the server, not the host, decides whether a profile is gated — 403'd and killed Connect for every non-root principal before the session open was reached. |
| v1 vs v2 | v1 `session/open` takes caller-resolved `credential_material`; v2 additionally resolves `secret` / `ssh-engine` references server-side, which is what connect-only access needs. Both are gated, so both are grantable to a tenant. v1's **unbound** shape (no `resource_id`: arbitrary target host, caller-supplied credential, no object to authorize against) requires `sudo` on the path. The shared brokering engine is `brokered_session_open`, which authorizes nothing itself — every caller reaches it through one of the two gates. |
| Resolver gate | `policy/effective` and `dispatcher/preview` gate their caller-supplied `resource_id` with `may_view_resource` — deliberately broader than the connect gate (inventory record **or** the connect gate), because an SSH-engine profile needs no grant on the secret path. See the operator note below for why both halves are necessary. |
| Server-side resolution | When the caller passes a credential **reference** (`credential_source = {kind:"secret", secret_id:"…"}`) instead of raw `credential_material`, the handler reads `resources/secrets/<name>/<key>` via `core.router.handle_request` (server authority, bypasses the caller's ACL) and brokers it. The connect-only caller never reads it. Only the `ssh-password` shape is brokered server-side today — matching the bastion proxy's current capability. |
| Audit | The server-side read emits a `target: "security"` log line (`rustion-connect-resolve: user=… resource=… key=…`) attributed to the connecting operator. |
| GUI capability lookup | `v2/sys/capabilities-self` (`handle_capabilities_self`, `src/modules/system/mod.rs`; HTTP shim `/v2/sys/capabilities-self`, v2-only) returns the caller's effective capabilities per path. Vault-compatible shape. Clients send **mount-relative** paths (`resources/secrets/<name>/`); the handler namespace-qualifies them before evaluating (`qualify_capability_path`) so the verdict matches what the router will decide, and keys the response by the path the caller sent. Header-scoped mounts (`sys/` `auth/` `identity/` `rustion/` `notifications/`) are exempt, exactly as in the router. Scope-gated capabilities are re-verified per path before they are reported — including `connect`, which needs its own pass because it maps to no `Operation` and so cannot go through `can_operate`. Left unverified it was the one capability that leaked its gate, and since the GUI reads this field to decide whether to render Connect, it rendered a button the server then refused. |
| GUI filtering | The Resources page queries capabilities for `resources/secrets/<name>/`; when the caller has `connect` but not `read`, it hides credential values (`ResourceSecretsPanel`) and restricts launchable connection profiles to the ones whose session is brokered (`ConnectionProfilesPanel`). |
| What counts as brokered | Two things, and **both** count: the profile's own `kind: "rustion"`, or an effective transport tier of `rustion-required` (or `rustion-preferred` with a resolved bastion). Reading only the profile's `kind` was a bug — it defaults to `direct` on every profile minted before the field landed, so a resource pinned to `rustion-required` by a *policy tier* had its connect-only callers refused the one connection that never touches their machine. The tier is resolved via `rustion/policy/effective` (`useEffectivePolicy`), and it only rescues the credential kinds `rustion/v2/session/open` resolves server-side — `secret`, `ssh-engine`, `default-account` — over SSH. |
| One launchability predicate | `isLaunchableForCaller` (`gui/src/lib/connectionProfiles.ts`) is the single answer to "would Connect do anything?" — the phase matrix plus the connect-only transport filter. The Connection tab, the resource card context menu, and `pickDefaultProfile`'s quick-Connect all call it, so the list can't offer a launch the detail view refuses. |
| Card-level gate | `resources/search` projects `connect_profiles` (protocol, transport, credential-source `kind`/`mode`) onto each card, and the Resources page resolves connect-only status for the whole visible page in one batched `capabilities-self` call (`useConnectOnlyMap`). A card with no profiles at all, or whose profiles are unlaunchable for a caller who *can* read credentials, renders Connect inert with the reason in its tooltip. For a **connect-only** caller the card stays live: the projection carries no effective transport, so the card cannot prove Connect is useless — `connectResource` resolves the transport on click and either launches the brokered profile or opens the Connection tab. The batched probe is advisory only — it never fails closed, because `connectResource` re-checks the capability authoritatively before dialling. |

## Phases

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | `connect` capability; secondary connect gate + `rustion/v2/session/open` with server-side `secret`-kind resolution; `v2/sys/capabilities-self`. Unit + integration tests. | **Done** |
| 2a | GUI: `capabilities_self` Tauri command + `api.capabilitiesSelf`; hide credentials + restrict to Rustion profiles for connect-only users; connect-only notices. | **Done** |
| 2c | GUI: extend the connect-only gate to the *list* — card / context-menu / quick-Connect share `isLaunchableForCaller`, `connect_profiles` on the card projection, batched capability probe, and the read-only + connect-only notices collapsed into one. | **Done** |
| 2b | GUI: the SSH Rustion connect path sends a credential reference to `rustion/v2/session/open` for `secret`-backed profiles (no client-side read). See below. `default-account` joins `secret` / `ssh-engine` on that path — it is an `ssh-engine` mint whose principal is the operator's own account, resolved from the self-service `sys/identity/default-account/self`. | **Done** |
| 2d | Gate parity + share awareness: v1 `session/open` gains the same per-resource gate (its unbound shape now needs `sudo`), the gate itself learns ownership- and share-derived access via `PolicyStore::readable_targets`, the read-only resolvers gate their `resource_id` with the broader `may_view_resource`, and the GUI launch gate keys off the *effective transport tier* rather than the profile's stored `kind`. | **Done** |
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
same as any other Rustion session-open caller. **Namespace-bound tokens are the
exception** — they cannot be granted `rustion/*` at all (root owns the path;
`refuse_cross_namespace_paths` rejects the rule), so the implicit
`namespace-self` policy carries `rustion/session/open`,
`rustion/v2/session/open`, `session/renew`, `session/kill`, the read-only
resolvers, and `read` on `rustion/targets/+`. It confers no `sudo`, so v1's
unbound fleet-proxy shape stays out of a tenant's reach. See the resolved open
question in `features/rustion-integration.md`.

Do **not** narrow `rustion/policy/effective` below the baseline the `default`
and `namespace-self` policies grant. It is the resolver the connect path uses to
decide whether a session routes through a bastion, and it now fails closed: a
caller who can't reach it is refused the dial outright rather than guessing at
the transport (which is what previously let a `rustion-required` resource be
dialled direct).

**The resolvers are gated per resource** (`may_view_resource`). They take a
caller-supplied `resource_id`, so ungated they let any holder of the baseline
grant enumerate the transport tier and fronting bastions of every resource in
the deployment — fleet topology rather than credentials, but no reason to hand
it out. Two constraints shaped the check, and the obvious version violates
both:

1. **`PolicyStore::readable_targets`, not `ACL::explain_capability`.** The
   latter's identity-less dry-run fails every scope-gated rule closed, so it
   reports "denied" for exactly the callers whose access comes from a share or
   from owning the resource. Gating that way would 403 them — and because
   `read_effective_policy` fails closed, their Connect would break outright,
   including on plain direct-transport resources.
2. **"May view this resource", not the secret path.** A profile whose credential
   comes from the SSH engine (`ssh-engine` / `default-account`) needs no grant
   on `resources/secrets/<name>/` at all, so checking that path alone would
   refuse a caller who can legitimately connect. The condition is
   `readable_targets` on `<ns>/resources/resources/<name>` **or** the
   `may_connect_resource` gate (the connect-only shape, whose grant *is* scoped
   to the secret path).

Tier-only resolution (`resource_type` / `asset_group_ids` with no `resource_id`)
stays ungated: no object to authorize against, and the answer is the
admin-authored tier chain the caller's own sessions already obey.
