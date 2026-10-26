# API Reference

BastionVault exposes a RESTful HTTP API compatible with HashiCorp Vault. All API routes are under the `/v1/` prefix.

Authentication is provided via the `X-Vault-Token` header or a `token` cookie.

## System Endpoints

### Initialization

**Check initialization status**

~~~
GET /v1/sys/init
~~~

~~~json
{ "initialized": true }
~~~

**Initialize the vault**

~~~
PUT /v1/sys/init
~~~

Request body:

~~~json
{
  "secret_shares": 5,
  "secret_threshold": 3
}
~~~

Response:

~~~json
{
  "keys": ["abcd1234...", "efgh5678...", "..."],
  "root_token": "s.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
~~~

### Seal Status

~~~
GET /v1/sys/seal-status
~~~

~~~json
{
  "sealed": false,
  "t": 3,
  "n": 5,
  "progress": 0
}
~~~

### Seal

~~~
PUT /v1/sys/seal
~~~

Requires a valid token with root privileges.

### Unseal

~~~
PUT /v1/sys/unseal
~~~

Request body:

~~~json
{
  "key": "7df5ff90cd9417e04cbb9f6db65e0b16ce265d5108fd07e45bdae1a35bf5da6a"
}
~~~

Response:

~~~json
{
  "sealed": false,
  "t": 1,
  "n": 1,
  "progress": 0
}
~~~

### HSM Seal Status

Reports the active seal provider. With no `hsm "…"` block configured the vault
uses the classic Shamir operator-unseal; configuring an HSM seal enables
hardware-backed auto-unseal. Read-only; never returns secret material. See
`features/hsm-support.md`.

~~~
GET /v2/sys/hsm/status
~~~

Shamir (default) response:

~~~json
{
  "type": "shamir",
  "auto_unseal": false,
  "sealed": false,
  "initialized": true
}
~~~

HSM seal response:

~~~json
{
  "type": "hsm",
  "auto_unseal": true,
  "backend": "yubihsm2",
  "device_serial": "0012345678",
  "hsm_id": "yubihsm2:0012345678",
  "node_id": "node-a",
  "cluster_uuid": "…",
  "epoch": 0,
  "topology": "per-node",
  "enrolled_nodes": 3,
  "this_node_enrolled": true,
  "recovery": "none",
  "recovery_requested": "none",
  "recovery_configured": false,
  "seal_record_version": 2,
  "pqc_key_cache_ttl_secs": 60,
  "sealed": false,
  "initialized": true
}
~~~

- `topology` — `per-node` (one device per node) or `pool` (two shared devices,
  [HSM pool HA](../features/hsm-pool-ha.md)).
- `recovery_requested` — the `recovery` value in config (`recovery` is the same
  value, kept for older clients). `recovery_configured` is `true` only when the
  seal record holds a recovery key; it is never inferred from config.
- `seal_record_version` — `1` for a record written before T454 and not yet
  rewritten, `2` otherwise; `null` before init.

HSM pool response (`topology = "pool"`; T454 phase 2). There is no single
`device_serial` / `hsm_id`; each member reports its own:

~~~json
{
  "type": "hsm",
  "auto_unseal": true,
  "backend": "mock",
  "node_id": "vault-3",
  "topology": "pool",
  "min_wrap_copies": 1,
  "members": [
    {
      "name": "hsm-a",
      "hsm_id": "mock:MOCK-A",
      "serial": "MOCK-A",
      "state": "active",
      "up": true,
      "faulted": false,
      "prefer": false,
      "holds_kek_copy": true,
      "last_error": null
    },
    {
      "name": "hsm-b",
      "hsm_id": "mock:MOCK-B",
      "serial": "MOCK-B",
      "state": "active",
      "up": false,
      "faulted": false,
      "prefer": false,
      "holds_kek_copy": true,
      "last_error": "probe: HSM transport or session failure: mock HSM MOCK-B is unreachable"
    }
  ],
  "under_replicated_sets": 0,
  "kek_under_replicated": false,
  "cluster_uuid": "…",
  "epoch": 0,
  "seal_record_version": 2,
  "seal_record_topology": "pool",
  "recovery": "none",
  "recovery_requested": "none",
  "recovery_configured": false,
  "pqc_key_cache_ttl_secs": 60,
  "sealed": false,
  "initialized": true
}
~~~

- Members come from the seal record once one exists (`state` is its member
  state); before init they are the config's bootstrap list (`state:
  "bootstrap"`). `up` is `false` while the member's circuit breaker is open or
  it is `faulted` (the device behind its path is not the recorded one).
- `under_replicated_sets` counts the KEK set only; custody sets are counted by
  the custody store and exported as `bv_hsm_under_replicated_sets`.
- `last_error` is the member's last failure (operation and error class); it
  never carries key material.

CLI equivalent: `bvault operator hsm status`.

### Mounts (Secrets Engines)

**List all mounts**

~~~
GET /v1/sys/mounts
~~~

**Mount a secrets engine**

~~~
POST /v1/sys/mounts/{path}
~~~

Request body:

~~~json
{
  "type": "kv",
  "description": "Key-value store",
  "config": {
    "default_lease_ttl": "1h",
    "max_lease_ttl": "24h"
  }
}
~~~

**Unmount a secrets engine**

~~~
DELETE /v1/sys/mounts/{path}
~~~

**Remount a secrets engine**

~~~
POST /v1/sys/remount
~~~

Request body:

~~~json
{
  "from": "secret/",
  "to": "generic/"
}
~~~

### Auth Methods

**List enabled auth methods**

~~~
GET /v1/sys/auth
~~~

**Enable an auth method**

~~~
POST /v1/sys/auth/{path}
~~~

Request body:

~~~json
{
  "type": "userpass",
  "description": "Username/password authentication"
}
~~~

**Disable an auth method**

~~~
DELETE /v1/sys/auth/{path}
~~~

### Leases

Vault's lease paths on the system backend. The `/v1/sys` and `/v2/sys` HTTP
scopes do not route them, so a plain `PUT /v1/sys/revoke/{lease_id}` answers
`404`. They are served in-process (embedded vault mode, the in-process API) and
through `POST /v2/sys/batch`, one `write` operation per call. Vault's newer
`sys/leases/*` paths, which `vault lease revoke` uses, are not implemented.

~~~json
POST /v2/sys/batch
{
  "operations": [
    { "operation": "write", "path": "sys/revoke/kv/app/db/0f3c2a6e-…" }
  ]
}
~~~

A successful revocation is `204` in the operation's result. Inside a batch, a
refusal currently reports `500` with the reason in `errors`; the statuses below
are the ones the handlers raise.

Lease ids share one deployment-wide keyspace, so these endpoints are not
namespace-scoped yet. A request whose `X-BastionVault-Namespace` names a child
namespace is refused with `400`, and a token bound to a child namespace with
`403`. A namespaced secret's lease id starts with its namespace path, so a
root-namespace operator revokes it by its full id.

**Revoke a lease**

~~~
sys/revoke/{lease_id}            (write)
~~~

Needs `update` on `sys/revoke/{lease_id}`. Revokes the lease and deletes its
record. Revoking a token's lease revokes the token and its children. `400` when
no lease has that id (nothing was revoked), or when the id is empty, absolute or
contains `..`. A secret backend's revoke error is still logged and the lease
record removed anyway; every secret type in the tree revokes with a no-op today.

**Revoke every lease under a prefix**

~~~
sys/revoke-prefix/{prefix}       (write)
~~~

Needs `update` **and `sudo`** on `sys/revoke-prefix/{prefix}`. Revokes every
lease under `{prefix}/`, matched on whole path segments: `kv/team-a` does not
touch `kv/team-ab/…`. As in Vault, a prefix with no leases under it is not an
error.

**Renew a lease**

~~~
sys/renew/{lease_id}             (write)
~~~

Not implemented: always `501`. Renew a token with `auth/token/renew-self` or
`auth/token/renew`. Lease renewal lands with the dynamic-secrets framework.

### Policies

**List all policies**

~~~
GET /v1/sys/policy
~~~

~~~
GET /v1/sys/policies/acl
~~~

**Read a policy**

~~~
GET /v1/sys/policy/{name}
~~~

**Write a policy**

~~~
POST /v1/sys/policy/{name}
~~~

Request body:

~~~json
{
  "policy": "path \"secret/*\" { capabilities = [\"read\", \"list\"] }"
}
~~~

**Delete a policy**

~~~
DELETE /v1/sys/policy/{name}
~~~

**Dry-run a draft policy** (graphical builder / validator)

Parse a *draft* policy and evaluate `(path, capability)` cases against it
using the production parser and ACL matcher, **without persisting**.
Requires the same capability as a policy write (`sys/policies/acl/*`).
`test` is a reserved policy name because of this route.

~~~
POST /v2/sys/policies/acl/test
~~~

Request body:

~~~json
{
  "policy": "path \"secret/data/*\" { capabilities = [\"read\", \"list\"] }",
  "name": "team-reader",
  "cases": [
    { "path": "secret/data/x", "capability": "read" },
    { "path": "secret/data/x", "capability": "delete", "policies": ["default", "totp-admin"] }
  ]
}
~~~

`name` is the name the draft would be saved under. It is optional but
recommended: it is what `granting_policies` reports for the draft's own
rules, and it is how an attached policy that *is* the draft is recognized
and skipped (so editing `default` does not merge the stored copy back in
underneath).

Per case, `policies` names the policies a real token would carry alongside
the draft; all of them are built into one ACL and evaluated together, so
the verdict matches what a token actually gets. It is tri-state:

| `policies` | meaning |
|---|---|
| absent / `null` | `["default"]` — what a normal token carries |
| `[]` | the draft alone |
| `["a", "b"]` | the draft plus exactly those |

Naming `root` is rejected with `400`: root is a synthetic superuser policy
that allows every path, so the dry-run would be meaningless. Naming a policy
the caller cannot `read` on `sys/policies/acl/<name>` is rejected with `403`
— attaching a policy reads it, and the endpoint must not become a read
oracle for one the caller could not fetch directly. It fails rather than
evaluating a narrower ACL, since an optimistically-wide verdict is the
failure this field exists to prevent.

Response (`parse_ok = false` with `errors` when the draft fails to parse):

~~~json
{
  "parse_ok": true,
  "errors": [],
  "results": [
    {
      "path": "secret/data/x",
      "capability": "read",
      "allowed": true,
      "matched_path": "secret/data/*",
      "match_kind": "prefix",
      "denied_by_deny": false,
      "granting_policies": ["team-reader"],
      "evaluated_policies": ["team-reader", "default"],
      "missing_policies": [],
      "draft_only_allowed": true
    }
  ]
}
~~~

`match_kind` is one of `exact` | `prefix` | `segment_wildcard` | `none`.
`matched_path`, `match_kind` and `granting_policies` are advisory;
`allowed` / `denied_by_deny` are authoritative (produced by the real
matcher).

`granting_policies` names the policies that contributed the rule at
`matched_path`. It is a list because capabilities are unioned **only**
between rules whose path string is identical; across different path strings
precedence picks exactly one winning rule. That is why a narrow rule in an
attached policy *replaces* a broad rule in the draft rather than adding to
it — and `draft_only_allowed` (the verdict the draft alone would give)
disagreeing with `allowed` is precisely that narrowing. `missing_policies`
lists named policies that do not exist in the namespace, so a caller is
never misled by an ACL narrower than the token it models.

**Read / write saved test cases**

Effectivity test cases attached to a policy (documentation of intent + a
save-time regression gate). Stored alongside, not inside, the policy HCL.

~~~
GET  /v2/sys/policy-tests/{name}
POST /v2/sys/policy-tests/{name}
~~~

Write body (an empty `cases` array clears them):

~~~json
{
  "cases": [
    { "path": "secret/data/x", "capability": "read", "expect": "allow", "note": "sre reads" },
    { "path": "secret/data/x", "capability": "delete", "expect": "deny", "policies": ["default"] }
  ]
}
~~~

A case may carry the same optional `env` and `policies` fields the dry-run
accepts; the save-time regression gate replays them, so a saved case gates
on the same multi-policy verdict it was authored against. `policies` keeps
its tri-state on the round trip — a case saved without it reads back
without it, which is not the same as reading back `[]`.

### Server Info

Returns identity + lifecycle facts the GUI's *Server Info* dialog
also reads. Useful for monitoring tooling that wants a single
endpoint covering version, uptime, and storage flavour.

~~~
GET /v1/sys/info
~~~

The endpoint answers without a token, but the payload has two
disclosure tiers. `initialized` and `sealed` are always returned —
callers need them before a token can exist (`bvault status` against a
fresh vault, the GUI connect screen). The build-fingerprinting fields
are returned **only** to a caller presenting a live token, because an
exact version maps straight onto known CVEs and `started_at` /
`uptime_seconds` leak patch cadence. Any valid token unlocks them; no
particular policy is required.

Unauthenticated response:

~~~json
{
  "initialized": true,
  "sealed": false
}
~~~

Authenticated response:

~~~json
{
  "initialized": true,
  "sealed": false,
  "version": "0.5.20",
  "started_at": "2026-05-14T18:00:00Z",
  "uptime_seconds": 3712,
  "storage_type": "hiqlite"
}
~~~

The restricted fields are **omitted**, not nulled, so the anonymous
body is a strict subset of the authenticated one. Clients should read
them defensively. For unauthenticated liveness/seal probing (load
balancers, readiness checks), `GET /v1/sys/health` remains the
purpose-built endpoint.

### Cluster Status

~~~
GET /v1/sys/cluster-status
~~~

~~~json
{
  "storage_type": "hiqlite",
  "cluster": true,
  "node_id": 2,
  "is_leader": false,
  "cluster_healthy": true,
  "raft_metrics": { }
}
~~~

Gated. The payload names the Raft leader and enumerates cluster
membership, which for a secrets manager is target selection — it points
at the single highest-value node to attack or disrupt — so it is not an
anonymous route. A caller qualifies either by presenting a live token
(any valid token; no particular policy required) or by connecting *from
one of the cluster's own machines*: the request's TCP source address is
loopback, or it appears in the storage backend's configured `nodes`
list. That exception is what keeps `bvault status` working when an
operator runs it on the server itself with no token in the environment.
Everyone else gets `403`.

The check uses the socket peer address, never an `X-Forwarded-For`
value, so it cannot be claimed with a header. Peer hostnames from
`nodes` are re-resolved periodically (30s), so a peer that restarts on a
new address keeps qualifying.

Note that unlike `sys/info`, no field here is tiered for anonymous
callers — `storage_type` is precisely what `sys/info` withholds, so
returning it here would reopen that disclosure.

`storage_type` is reported by the backend itself and is one of `file`,
`mysql`, `hiqlite` or `mock`; `unknown` means a backend that does not name
itself, never a guess. `cluster` is `true` only when the physical backend
really is a Raft cluster, and `node_id` / `is_leader` / `cluster_healthy` /
`raft_metrics` are **omitted** rather than defaulted when it is not. Up to
and including 0.41.18 these fields were inferred from the reporting
crate's own compile-time features, and a clustered node answered
`{"storage_type": "file", "cluster": false}`; do not treat that response
from an older server as ground truth about the storage layer.

### Identity Groups

User-group and AppID-group records that fan policies out to every
member at login time.

~~~
LIST   /v1/identity/group/user
GET    /v1/identity/group/user/{name}
PUT    /v1/identity/group/user/{name}
DELETE /v1/identity/group/user/{name}
GET    /v1/identity/group/user/{name}/history

LIST   /v1/identity/group/app
GET    /v1/identity/group/app/{name}
PUT    /v1/identity/group/app/{name}
DELETE /v1/identity/group/app/{name}
GET    /v1/identity/group/app/{name}/history
~~~

Write body:

~~~json
{
  "description": "Platform engineering",
  "members": ["alice", "bob", "felipe2"],
  "policies": ["engineering-shared"]
}
~~~

### Sharing

Per-target CRUD plus a caller-introspecting feed. `target` is
`base64url(no-pad)` of the canonical target path so KV paths
containing slashes fit a single URL segment.

~~~
GET    /v1/identity/sharing/by-target/{kind}/{target}/{grantee}
PUT    /v1/identity/sharing/by-target/{kind}/{target}/{grantee}
DELETE /v1/identity/sharing/by-target/{kind}/{target}/{grantee}
LIST   /v1/identity/sharing/by-target/{kind}/{target}
LIST   /v1/identity/sharing/by-grantee/{grantee}
LIST   /v1/identity/sharing/for-me
~~~

Put body:

~~~json
{
  "target_kind": "kv-secret",
  "target_path": "secret/app/db",
  "grantee_kind": "group_user",
  "capabilities": ["read", "list"],
  "expires_at": "2027-01-01T00:00:00Z"
}
~~~

- `grantee_kind`: `entity` (default) | `group_user` | `group_app`.
- `target_kind`: `kv-secret` | `resource` | `asset-group` | `file`.

`identity/sharing/for-me` returns the caller's direct entity shares
plus group shares the caller is entitled to (group shares only
surface when at least one of the caller's policies carries
`metadata.group_shared_resources = "true"`):

~~~json
{
  "entity_id": "08c9c6d3-...",
  "group_shared_resources": true,
  "entries": [
    { "target_kind": "resource",   "target_path": "server-01",   "grantee_kind": "entity" },
    { "target_kind": "kv-secret",  "target_path": "secret/app/db", "grantee_kind": "group_user" }
  ]
}
~~~

### Caller introspection

~~~
GET /v1/identity/entity/self
~~~

Returns the caller's `entity_id`, `username`, `mount_path`,
`role_name`, and (when the entity record exists) `primary_mount`,
`primary_name`, `created_at`, and `aliases[]`. Lazily resolves the
entity from the caller's alias if the token's metadata has no
`entity_id` yet.

### Self-Service Profile

Everything a signed-in operator may change about their own account
without an administrator. Every route resolves the principal from the
request token — none of them take a username, and none can reach another
operator's record. **v2-only.** Granted to every authenticated token by
the built-in `default` policy (see `features/self-service-profile.md`).

~~~
GET  /v2/sys/identity/profile/self
POST /v2/sys/identity/profile/self/password
POST /v2/sys/identity/profile/self/contact
GET  /v2/sys/identity/default-account/self
POST /v2/sys/identity/default-account/self
~~~

**Read the profile.** Never 404s: a token with no userpass login behind
it (root, `auth/token/create` child, AppRole, OIDC) still gets a
well-formed document with the `can_*` flags false.

~~~json
{
  "username": "alice",
  "auth_mount": "auth/pass/",
  "auth_method": "userpass",
  "entity_id": "…",
  "policies": ["standard-user", "default"],
  "email": "alice@example.com",
  "phone": "+55 21 1234-5678",
  "disabled": false,
  "fido2_enabled": false,
  "totp_mfa_enabled": false,
  "can_change_password": true,
  "can_edit_contact": true,
  "can_edit_default_account": true,
  "default_account": {
    "mount": "userpass/", "name": "alice",
    "linux": "alice-svc", "macos": "", "windows": "CORP\\alice",
    "has_windows_password": true,
    "updated_at": "2026-07-01T00:00:00Z"
  }
}
~~~

The auth mount is recovered from the token's own login path, so it names
the mount that actually issued the token (`auth/pass/`) rather than the
`userpass/` literal every userpass mount stamps into token metadata.

**Change your own password.** Both fields required; the current password
is verified before anything is written. Refused (400) when the token did
not come from a userpass login, when the account is FIDO2-only, and when
the new password is shorter than 8 characters or equal to the current
one; 403 when the account is disabled or the current password is wrong.
A wrong current password is recorded on the user-audit trail but does
**not** feed the account-lockout counter — otherwise anyone holding a
live token could lock its owner out. Sessions issued before the change
are not revoked.

~~~json
{ "current_password": "…", "new_password": "…" }
~~~

**Contact details.** Write-preserve: a field absent from the body keeps
its stored value, an empty string clears it. Informational only — never
used for authentication, notification, or account recovery.

~~~json
{ "email": "alice@fgv.br", "phone": "+55 21 9999-0000" }
~~~

**Your own default resource accounts.** The caller-scoped sibling of the
admin `/{mount}/{name}` route below. Every field is write-preserve, so a
partial update is safe and re-saving without retyping the stored Windows
RDP password does not wipe it; clearing every field deletes the record.
The write response masks the password (`has_windows_password` only). The
`GET` is the one place the stored password is returned, and only ever to
its own owner — the connect host injects it into the RDP session.

~~~json
{ "linux": "alice-svc", "windows": "CORP\\alice", "windows_password": "…" }
~~~

### Connect-Only Access

The `connect` capability lets a policy grant the ability to open a
Rustion-brokered session to a resource **without** read access to its
stored credentials:

~~~hcl
path "resources/secrets/db-prod/*" {
  capabilities = ["connect"]
}
~~~

`read` and `root` imply `connect`. The credential is resolved server-side
and injected by the bastion; the connect-only caller never reads it.

**Effective capabilities (v2-only):**

~~~
POST /v2/sys/capabilities-self
~~~

Body `{ "paths": ["resources/secrets/db-prod/"] }`. Returns the caller's
capability strings per path (Vault-compatible): a top-level `capabilities`
map plus per-path keys. The GUI uses this to hide credential values when a
caller has `connect` but not `read`.

**Connect-only session open (v2-only):**

~~~
POST /v2/rustion/session/open
~~~

Enforces `connect`/`read`/`root` on `resources/secrets/<resource_name>/`
before resolving credentials. When given a credential reference instead of
raw `credential_material`, BastionVault resolves the secret server-side:

~~~json
{
  "resource_name": "db-prod",
  "credential_source": { "kind": "secret", "secret_id": "ssh" },
  "target_host": "10.0.0.5",
  "target_port": 22,
  "target_protocol": "ssh"
}
~~~

The `secret` (ssh-password shape), `ssh-engine` and `provider` credential
kinds are resolved server-side; `provider` takes `provider_account_id` (see
*Credential providers at Connect* below). v1 `POST /v1/rustion/session/open`
(raw `credential_material`) is unchanged.

### SQL privileges (policy and share vocabulary)

Eleven capabilities grant SQL privileges on a database resource for the SQL
browser ([features/sql-browser.md](../features/sql-browser.md) §3, T124):
`sql_select`, `sql_insert`, `sql_update`, `sql_delete`, `sql_alter`,
`sql_create`, `sql_drop`, `sql_execute`, `sql_admin`, `sql_export` and
`sql_script`. They are probe-only, like `connect`: no request operation needs
one, no other capability implies one (`read`, `update`, `sudo` and `connect`
grant none), none implies another, and an applying `deny` revokes them. Only
the root token holds them all implicitly.

They are evaluated on synthetic paths under the resource, which are never
routed. The resource name is the lower-case canonical name:

~~~
resources/resources/<resource>/sql/server
resources/resources/<resource>/sql/objects/<catalog>/<schema>/<object>
~~~

~~~hcl
path "resources/resources/netrisk-db/sql/*" {
  capabilities = ["sql_select"]
}
~~~

A rule that lists a SQL capability cannot also set `allowed_parameters`,
`denied_parameters` or `required_parameters`; the policy is refused. An
object whose name contains `/`, `*`, `+` or a control character, or is empty,
`.` or `..`, is checked on `…/sql/objects/` instead, so only a grant covering
every object applies to it.

Shares on `resource` and `asset-group` targets accept the same eleven names
(`identity/sharing/…`, `capabilities`). On `kv-secret` and `file` targets a
SQL capability is refused with a `400`; it is not dropped. A share takes
effect through the share-scoped rule on `resources/resources/+/sql/*` in the
`default`, `namespace-shared` and `shared-access` baselines, which conveys
exactly the `sql_*` entries the share names. Owning the resource record grants
no SQL privilege.

No HTTP route uses these yet. The SQL browser's host calls and the
`resources/v2/sql/privileges/<resource>` read land with the later Phase 1
steps of T124. A refused check made for a plugin is recorded on the Audit
page's denied view with `reason=sql-privilege`, the capability, the namespace
and the plugin name.

### Web Connect (`form` and `http-auth` modes)

Server half of [Web Application Connect](../features/web-application-connect.md)
§3 and §7: four `POST` endpoints on the resource mount (v2 only). The desktop
host calls `launch` **instead of** `connect/authorize` for a `web` profile
whose `login_mode` is `form` or `http-auth` — `launch` burns the MFA ticket
itself. Every refusal
is an HTTP error whose message starts with a stable code (`<code>: …`); the
codes are listed per endpoint.

A profile's `web.tls_pin_sha256` (TLS SPKI pins, Phase 4) is a desktop-host
setting: the server stores it with the profile but neither reads nor
validates it, and `launch` does not return it. New `aborted:<check>` values
the host may send to `result`: `tls_handler` (the pin handler could not be
attached; nothing was loaded), and `tls_pin_mismatch`, `tls_pin_issuer`,
`tls_pin_malformed` or `tls_pin_no_certificate` when the session ends before
its sign-in outcome after a certificate was refused.

**Re-run login (Phase 5, desktop build feature `web_session_chrome`).** The
web session toolbar's **Re-run login** on a `form` session makes a **new**
`launch` (new `launch_id`, the same authorisation, a fresh credential) with the
recipe hash the session was opened with — no endpoint is added and nothing is
replayed. It sends no `connect_ticket` (the ticket is single-use and the
toolbar runs no MFA ceremony), so on a profile gated on connect MFA the server
refuses it and the session keeps its current launch. Once the new launch is
accepted, the previous one is `result`-ed `aborted:relogin` if its recipe had
not reported, then `close`d (an LDAP account is checked back in). The toolbar
reaches the host through three Tauri commands that take no arguments and act
only on the session whose window hosts the calling toolbar:
`web_chrome_state`, `web_chrome_disconnect` and `web_chrome_relogin`.

The caller needs `update` on the endpoint paths **and** `connect` (or `read`
/ `root`) on `resources/secrets/<resource>/`. The built-in baseline policies
(`default`, `shared-access` and the namespace baselines) grant `update` on
`connect/web/{launch,totp,result,close}` alongside `connect/mfa/*` and
`connect/authorize`, so only the per-resource `connect` grant is needed. A
custom policy that wants the endpoint grant without the baseline can state it
explicitly:

~~~hcl
path "resources/v2/connect/web/*" { capabilities = ["update"] }
path "resources/secrets/fw01/*"   { capabilities = ["connect"] }
~~~

**`POST /v2/resources/v2/connect/web/launch`**

~~~json
{ "resource": "fw01", "profile_id": "p_web",
  "recipe_hash": "sha256:9f2c…", "connect_ticket": "…" }
~~~

- `recipe_hash` (required for `form`) is `sha256:` + lowercase hex SHA-256 of
  the RFC 8785 (JCS) canonical JSON of the profile's `web.recipe` exactly as
  stored. Reuse `bastion_vault::modules::resource::connect_web::recipe::recipe_hash`.
  A mismatch means the profile changed since the host loaded it. An
  `http-auth` profile has no recipe: its launch must **not** carry
  `recipe_hash` (`recipe_hash_unexpected`, 400).
- `connect_ticket` is required only when the profile has `require_mfa`.

Response:

~~~json
{
  "launch_id": "<43-char base64url>",
  "expires_at": "2026-10-05T12:01:00Z",
  "resource": "fw01", "profile_id": "p_web",
  "login_mode": "form", "exposure": "dom", "exposure_cap": "dom",
  "recipe_hash": "sha256:9f2c…", "heuristic": false,
  "fill_scope": { "start_url": "https://fw01.example.com/login",
                  "origins": ["https://fw01.example.com"],
                  "allow_insecure_http": false },
  "credential_source": "secret",
  "credential": { "username": "admin", "password": "…",
                  "totp": "123456", "totp_valid_until": "2026-10-05T12:00:30Z" },
  "totp_refresh_steps": [1],
  "mfa_method": "totp"
}
~~~

- `http-auth` response: the same shape **without `recipe_hash`**, with
  `login_mode: "http-auth"`, `exposure: "handler"` (`"dom"` when the profile
  sets `allow_insecure_http`, see below), `heuristic: false`,
  `totp_refresh_steps: []` and `credential: { "username", "password" }` —
  never a TOTP code. `fill_scope` is the set of origins whose HTTP
  authentication challenges the host may answer; the host answers Basic,
  Digest and NTLM challenges natively (never through the page), once per
  (origin, realm), and refuses Kerberos/Negotiate, client certificates and
  proxy challenges. The launch record has no recipe step, so `result` takes
  no `step` (`invalid_step`, 400) and `totp` always refuses
  (`totp_not_configured`, 409).
- `credential` carries **only what the login uses** (`form`: what the recipe
  fills — `username`, `password`, `totp`, heuristic mode taking whichever the
  source has; `http-auth`: `username` and `password`, both required). It
  travels in plaintext in this response body over the API's TLS channel —
  the host holds it in `Zeroizing` buffers and drops it after
  success / failure / timeout. The TOTP seed never leaves the server. The
  audit pipeline records the response HMAC-redacted.
- `fill_scope` is the **authoritative fill scope**, bound to the launch:
  the profile's start URL and its normalised origin set (`scheme://host[:port]`,
  start origin first) as the server checked them. `recipe_hash` does not
  cover these profile fields, and in heuristic mode they are the only
  constraint on where a fill happens, so the host **must** start at
  `fill_scope.start_url` and fill **only** on a top-frame origin in
  `fill_scope.origins` (`http` only when `allow_insecure_http`) — never on
  origins from its own copy of the profile.
- `launch_id` is single-use per operation, stored server-side as its
  SHA-256 only, and bound to (principal, namespace, resource, profile,
  `recipe_hash`, `fill_scope`). The principal is the first of: `username`
  on a known auth mount; `entity:<entity_id>`; `token:<sha256 of the client
  token>` (this token store has no accessor); `name:<display_name>` on a
  known auth mount. A display name with no mount never binds.
  `expires_at` ends the **login window** (60 s): TOTP refreshes are issued
  only inside it. `result` and `close` are accepted until the session
  closes. Follow-up calls on one launch are serialised per server process;
  on a multi-node deployment serving requests from more than one node,
  concurrent calls on different nodes are not excluded.
- Credential sources: `secret` (keys `username`, `password`, optional
  `totp_seed` — base32 — remappable with
  `credential_source.fields = {username?, password?, totp_seed?}`; TOTP
  parameters in `credential_source.totp = {algorithm: SHA1|SHA256|SHA512,
  digits: 6|8, period: 30|60}`, default SHA1/6/30) is read under the
  server's authority, so a connect-only caller never needs `read`.
  `ldap` (`bind_mode` `static_role` or `library_set`) and `default-account`
  (username only, chosen by the resource's `os_type` like SSH) are resolved
  **as the caller**, through the caller's own grants on those paths.
  `http-auth` takes `secret` or `ldap` only: a `default-account` supplies no
  password and is refused (`credential_unavailable`, 422); TOTP settings on a
  `secret` source are validated but release nothing.
- Exposure policy — **deny unless opted in**: `web_exposure_max` (`none <
  isolated < handler < proxy < dom`) on the resource type
  (`config/types[<type>].connect`) and on the resource record (top-level
  key). The resource's `type` must name a type in the **saved**
  `config/types` that sets `web_exposure_max`; form mode needs `dom`,
  http-auth `handler` (so `handler`, `proxy` or `dom` admit it). An
  unset cap, a type missing from the saved configuration, or a
  configuration never saved leaves the cap at `none` and refuses with
  `exposure_not_permitted`. "Saved" means the resource mount's own
  `config/types`, or — for a child namespace whose mount has saved none —
  the root namespace's `resources/config/types`. A namespace that has saved
  any configuration is authoritative: there is no per-type fallback, so a
  tenant can deny where the root allows. `GET
  resources/v2/config/types/effective` returns what applies:
  `{ "source": "mount" | "root" | "none", "types": <saved object> | null }`. The resource tier can only lower the type's cap
  (`exposure_cap_exceeded`), never opt in by itself. An unreadable or
  unparseable `config/types`, or a value outside the enum, refuses with
  `exposure_policy_invalid`. `allow_heuristic_fill` on the same two tiers:
  an explicit `false` at either beats `true` at the other, and unset at both
  means no heuristics. `allow_insecure_http` is refused below a `dom` cap
  (`insecure_http_not_allowed`), in either mode — a credential sent over
  plain http is not `handler` exposure — and a launch that allows it is
  recorded and reported as `exposure: "dom"`. The GUI's built-in `web_application` and `website`
  types carry `web_exposure_max: "dom"`, so a type configuration saved by a
  current GUI opts them in; a configuration saved earlier keeps its types as
  saved and is denied until an administrator sets the cap.
- Rustion transport policy: the resource's effective policy (Rustion's own
  resolver over the global, type, asset-group and resource tiers — the
  `rustion/policy/effective` verdict) is checked before the MFA ticket is
  redeemed and before any credential is read. `rustion-required`, or any
  policy lock violation, refuses with `transport_policy` (403): a form or
  http-auth launch is always local, and there is no brokered web transport yet.
  `direct` and `rustion-preferred` are allowed; a resource with no policy at
  any tier resolves to `direct`. Rustion keeps its tiers in the system view,
  not in the mount, and they survive an unmount, so when the `rustion/`
  mount is unavailable (unmounted, or tainted mid-unmount or remount) the
  launch is allowed only if no Rustion policy record exists at all. A
  policy that cannot be resolved (records present without the mount,
  unreadable store, undecodable tier record, asset-group lookup failure,
  unknown verdict) refuses with `transport_policy_unavailable` (503) —
  never "allowed".
- Order, and what costs the MFA ticket. Every check above runs before the
  ticket is redeemed, and so do the credential pre-checks: a `secret`
  source is read and checked (the secret exists, carries what the recipe
  fills, and a decodable `totp_seed` when the recipe fills `totp`), a
  `default-account` is resolved, and an `ldap` source's mount must exist,
  be untainted and be an LDAP engine. Nothing is released before the
  ticket. What still fails after it, and so spends it: the LDAP
  static-credential read or library check-out (permission, an exhausted
  library, the directory), and persisting the launch. A check-out that
  returns an account but no password or lease is checked straight back in.
- Refusal codes: `wrong_protocol`, `wrong_login_mode`,
  `transport_unavailable`, `invalid_profile`, `invalid_recipe`,
  `credential_source_unsupported`, `recipe_hash_required`,
  `recipe_hash_mismatch`, `recipe_hash_unexpected`, `exposure_not_permitted`, `exposure_cap_exceeded`,
  `exposure_policy_invalid`, `heuristic_not_allowed`,
  `insecure_http_not_allowed`, `transport_policy`,
  `transport_policy_unavailable`, `mfa_required` (plus the ticket store's
  refusals), `credential_unavailable`, `totp_not_configured`,
  `resource_not_found`, `profile_not_found`; a missing connect grant is a
  plain `permission denied`.

**`POST /v2/resources/v2/connect/web/totp`** — `{ "launch_id": "…", "step": 1 }`

One fresh code per step listed in `totp_refresh_steps`, inside the login
window. Call it after `totp_valid_until` has passed. Response:
`{ "totp", "totp_valid_until", "step", "totp_refresh_steps" }` (the steps
still refreshable). Refusals: `launch_unknown` (404),
`launch_binding_mismatch` (403), `launch_expired` (410), `launch_closed`,
`totp_not_configured`, `totp_step_used`, `launch_busy` (409),
`totp_step_invalid` (400).

**`POST /v2/resources/v2/connect/web/result`** — `{ "launch_id": "…", "outcome": "success", "step": 1 }`

`outcome` is `success` | `failure` | `timeout` | `aborted:<check>` (check =
1–32 of `[a-z0-9_]`, e.g. `aborted:origin`, `aborted:form_action`); `step`
(optional) is the last step reached. Recorded once: repeating it returns
`already_recorded: true`, a different outcome is `result_conflict` (409).
Response: `{ "recorded": true, "already_recorded", "outcome" }`.

**`POST /v2/resources/v2/connect/web/close`** — `{ "launch_id": "…" }`

Idempotent. Records the session end and, when `launch` checked an LDAP
library account out, checks it back in **as the caller**. Response:
`{ "closed": true, "already_closed", "duration_ms",
"ldap_checkin": "not_applicable" | "done" }`. A failed check-in returns
`ldap_checkin_failed` (502); the close itself stands, and calling `close`
again retries the check-in.

Audit (`target: "audit"`): `connect.web.launch`, `connect.web.totp`,
`connect.web.result`, `connect.web.close`, `connect.web.refused`
(`op`, `reason`), `connect.web.reaped`, `connect.web.launch_rollback`. They
carry names, enum values, origins (`fill_origins`) and `launch_id_hash` (hex
SHA-256 of the `launch_id`) — never a credential, a TOTP code, a raw
`launch_id`, a full token hash, or a URL path or query. Expired records are
reaped from `launch`, at most once a minute per server process.

### Credential providers at Connect (v2)

A connection profile can take its credential from an approved
credential-provider plugin ([features/self-accounts.md](../features/self-accounts.md)
§6), the first being `bastion-plugin-self-accounts`:

~~~json
{ "credential_source": { "kind": "provider", "provider": "self-accounts" } }
~~~

The operator picks one of **their own** accounts in that provider, and the
server releases it on the Connect route. Every call needs the `connect` grant
on the resource (the baseline policies grant `update` on
`connect/provider/candidates` wherever they grant `connect/authorize`), an
identity-backed login (a token with no identity entity gets `403 no_entity`),
and a provider that is registered, active, not quarantined, admin-approved
(`v2/sys/plugins/{name}/grants/credential-provider`) and declares the
profile's protocol. Nothing falls back to another credential source.

**What the provider is told comes from the stored record, never the request.**
The resource `type` and `os_type`, and the target: for SSH / RDP the profile's
`target_host`, else the resource's `ip_address`, else its `hostname` — one
lower-case ASCII host, refused (`invalid_profile`) with a trailing dot, `*`,
`%`, brackets, whitespace or a `:` other than a bare IPv6 address — with the
profile's `target_port` or the protocol default (22 / 3389); for web every
origin the profile's recipe may fill (the start URL's origin and
`allowed_origins`). Accounts bound to other targets are neither offered nor
released, so a resource edited to point at another host gets nothing.

Every refusal on these paths is an HTTP error whose message starts with a
stable reason code: `no_entity`, `not_granted`, `unsupported_protocol`,
`no_match` (404: no account of yours matches, also a forged or stale id),
`mfa_required` (403: the provider releases only after connect-time MFA — set
`require_mfa` on the profile, or relax the provider's `require_connect_mfa`),
`bad_request` (400), `bad_provider_output` (502), `provider_error` (500),
`invalid_profile`, `invalid_request`, `transport_policy`,
`brokered_requires_ssh_engine` (403: the resource's SSH login class is
`brokered`, so every SSH login to it is minted by the SSH engine and no
provider account is listed or released for SSH; RDP and web are unaffected —
refused on `candidates`, `authorize` and `rustion/v2/session/open` before any
MFA ticket is redeemed).

**`POST /v2/resources/v2/connect/provider/candidates`** —
`{ "resource": "dc01", "profile_id": "p_rdp" }`. Any other body field is
ignored. Metadata only:

~~~json
{
  "resource": "dc01", "profile_id": "p_rdp",
  "provider": "self-accounts", "display_name": "Self-account",
  "protocol": "rdp", "resource_type": "server", "os_type": "windows",
  "target": { "host": "dc01.corp.example.com", "port": 3389 },
  "candidates": [
    { "id": "sa_…", "label": "Domain admin", "username": "felipe.adm",
      "domain": "CORP", "secret_kind": "password", "has_totp": false,
      "last_used_at": "2026-10-01T09:12:00Z",
      "first_use_on_target": false,
      "last_used_on_target": "2026-10-01T09:12:00Z" }
  ]
}
~~~

For a web profile `target` is `{ "origins": ["https://…", …] }`.

`first_use_on_target` is `true` when the provider has no record of releasing
that account for this target (the picker shows a caution), and
`last_used_on_target` is when it last did (the picker preselects the most
recent). Both are hints, never protections, and are `false` / absent when a
provider does not report them. The self-accounts plugin keeps only
domain-separated SHA-256 digests of targets (the canonical dial host for SSH /
RDP, the origin set for web), never the target text, and records a target only
on a successful release.

**`GET /v2/resources/v2/connect/providers`** — the providers a connection
profile can name, for the profile editor: every registered, active, not
quarantined and admin-approved provider, sorted by name. Declarations only; no
account, config or grant data:

~~~json
{
  "providers": [
    { "name": "self-accounts", "display_name": "Self-account",
      "protocols": ["ssh", "rdp", "web"], "secret_kinds": ["password", "ssh-key"] }
  ]
}
~~~

A server with no approved provider (or no plugin runtime) answers
`{ "providers": [] }`. The baseline policies (`default`, `shared-access`, the
namespace baseline, `administrator`) grant `read` on it; it takes no write.

**`POST /v2/resources/v2/connect/authorize`** gains `provider_account_id`
(direct SSH / RDP). It is required for a `provider` profile and refused
(`400 invalid_request`) for any other. Order: every check that can fail without
the provider runs first; then the MFA ticket is redeemed (and spent, whatever
happens next); then the provider releases. The release is refused with
`403 transport_policy` when the resource's Rustion transport policy is
`rustion-required` or carries a lock violation — such a credential is released
only through `rustion/v2/session/open`. For a `provider` profile the response
adds:

~~~json
{
  "credential_source": "provider", "provider": "self-accounts",
  "provider_account_id": "sa_…",
  "target": { "host": "dc01.corp.example.com", "port": 3389 },
  "credential": { "username": "felipe.adm", "domain": "CORP",
                  "secret": { "kind": "password", "password": "…" } }
}
~~~

`secret` is `{ "kind": "ssh-key", "private_key": "…" }` for a key account, and
never carries a TOTP seed. The released `username` is authoritative (the
profile's own `username` is ignored). The client must dial **exactly**
`target` with this credential, never another host candidate. No other profile's
response carries `credential` or `target`.

**`POST /v2/resources/v2/connect/web/launch`** gains `provider_account_id` for
a `form` profile with a `provider` source (`http-auth` refuses the source with
`credential_source_unsupported`). The bundle's `credential` carries the
released `username` and `password` and, when the recipe fills `totp` and the
account holds a seed, the current code; `credential_source` is `"provider"`.
`credential_source.totp` sets the TOTP parameters as for `secret`. A provider
seed is not kept server-side, so `totp_refresh_steps` is always `[]` and
`connect/web/totp` refuses. A heuristic recipe never asks the provider for a
TOTP.

**`POST /v2/rustion/session/open`** accepts
`credential_source = {"kind": "provider", "provider": "<plugin>"}` with
`provider_account_id` and `profile_id`. The source must equal the stored
profile's, `credential_material` must be absent, and `target_host` /
`target_port` / `target_protocol` must equal the stored target or be omitted —
they are overwritten with it. The server releases the account, seals it into
the envelope as `ssh-password`, `ssh-key` (unencrypted OpenSSH keys only; a
passphrase-protected key is refused) or `rdp-password` (a domain travels as
`DOMAIN\user`), and returns the usual ticket bundle; the caller never holds the
credential.

Audit (`target: "audit"`): `connect.provider.release` per release attempt and
`connect.provider.candidates` per listing, with `outcome` (`success` /
`denied`), `reason`, `principal`, `entity_id`, `resource`, `profile_id`,
`protocol`, `transport` (`direct` / `web` / `rustion`), `provider`,
`account_id`, `login_name` (successful releases) and `candidates` (count) —
never a secret or a TOTP code. `connect.web.launch` carries
`credential_source=provider provider="…"`, and Rustion's `session.open` line
names the credential source. The audit devices record the `authorize` and
`web/launch` responses HMAC-redacted, like every response. Metric:
`bvault_plugin_provider_requests_total{plugin, op, protocol, outcome}`
(`op` = `candidates` / `release`, `outcome` = `success` or a reason code).

**Desktop app (Tauri commands).** `connect_credential_providers()` wraps
`connect/providers`; `connect_provider_candidates(resource_name, profile_id)`
wraps `connect/provider/candidates` and returns metadata only, after the host
checked every string for plain-text display (a candidate whose label, login or
domain carries control or invisible formatting characters is withheld and
counted in `hidden`). `session_open_ssh`, `session_open_rdp` and
`session_open_web` take an optional `provider_account_id`: required for a
`provider` profile, refused for any other. On the direct path the host calls
`connect/authorize`, keeps the released secret in `Zeroizing` buffers inside
the host, and dials exactly the returned `target` (no fallback to another host
candidate, not even on a network error); no command returns the secret to the
webview; the released login and domain are held to the same plain-text rule
as the candidates, since they appear in the session's label. The host's
direct-path `session.open` audit line then adds
`credential_source=provider provider="…" account_id="…" login_name="…"`. A web
`form` session signed in with a provider account offers no toolbar sign-in
re-run: the provider releases again only after a new connect-time MFA check.

### Session Recordings + Keystroke Transcripts

~~~
GET  /v1/rustion/recordings
GET  /v1/rustion/recordings/{rid}
GET  /v1/rustion/recordings/{rid}/blob
GET  /v1/rustion/recordings/{rid}/blob/chunk/{n}
GET  /v1/rustion/recordings/{rid}/keystrokes
POST /v1/rustion/recordings/pull
POST /v1/rustion/recordings/reconcile
POST /v1/rustion/recordings/replay-log
POST /v1/rustion/recordings/keystrokes/index
POST /v1/rustion/recordings/keystroke-search
~~~

`{rid}` is always `rec_<hex>`.

**Authorization tiers matter here, and they are path-shaped.** The bare
`recordings/{rid}` route returns sidecar metadata; the recording's *bytes*
(`/blob`) and its *keystroke transcript* (`/keystrokes`) sit one segment
deeper. A policy granting `rustion/recordings/+` therefore reads metadata
only, while `rustion/recordings/*` grants the bytes and the transcript
together — which is the intended coupling, because a transcript is a record
of everything the operator typed and belongs with playback rather than with
"list sessions".

**`GET .../blob/chunk/{n}`** is the size-independent way to read a
recording's bytes, and the one the GUI player uses. It returns chunk `n`
of the artifact (4 MiB each) plus the geometry needed to keep going:
`size_bytes`, `chunk_index`, `chunk_count`, `chunk_size`, `offset`,
`chunk_len`, `eof`, and `bytes_b64` for that chunk only. `sha256` is the
digest of the **whole** artifact and repeats on every chunk, so a caller
verifies the assembled bytes exactly as it would from `/blob`. Read chunk
0, then read until `eof`; an index past the end is a `416`, and the error
states the real `chunk_count`. An empty artifact is one empty chunk, not
zero chunks.

**Both artifact routes verify the artifact before returning any of it.**
BastionVault hashes the bytes the bastion returned and compares them with
the digest on record for that recording — the sidecar's `sha256`, which
arrived over the signed `recording.ready` webhook, in preference to the
response's own `x-recording-sha256` header, which is supplied by the same
party as the bytes and so cannot vouch for them. A mismatch is a **`409`**
naming both digests; nothing is served and nothing is cached, so a chunked
read cannot be answered from a corrupted cache entry one slice at a time.
The `409` is deliberately not the `502` an unreachable or erroring bastion
produces: a digest mismatch is deterministic, a retry is not the remedy,
and the two need different operator responses. Refusals emit
`recording.artifact.rejected`, which is *not* `recording.replayed` — no
artifact reached a caller.

**`digest_verified`** (boolean, on `/blob` and every chunk) says whether
there was a digest to check against. `false` means the recording's sidecar
carries no `sha256`, so the bytes are served unverified and say so; it
never means "checked and failed", which is the `409` above. Recordings
whose sidecar landed without a digest therefore keep playing — the hard
failure is limited to recordings where a digest is known and the bytes
contradict it. A client is still expected to verify the artifact it
assembled against `sha256`: that check covers the vault-to-client leg,
which the server-side gate cannot.

`GET .../blob` (the whole artifact in one response) is unchanged and
still supported, but it cannot serve a recording larger than the
client's response-size limit — 4 MiB of artifact base64-expands to ~5.6
MB of body, and a 17.8 MB recording to ~23.7 MB, past the 10 MB default
of a stock ureq client. Prefer the chunk route for anything operator-
facing. Both routes sit under `rustion/recordings/*` and are granted by
the same policies; the chunk route is not a new capability surface for
the same data.

A GUI newer than its server falls back to `/blob` when the chunk route
is missing (the router reports `Logical backend path not supported.`),
so replay keeps working against an un-upgraded vault; it logs that it
did so, and a recording past the response limit still needs the server
upgrade.

Chunk reads of one recording are served from a bounded in-memory cache
in the engine (4 artifacts / 512 MiB, 180 s idle), because the bastion's
own blob endpoint serves whole files and honours no `Range` — without it
each chunk would re-download the artifact. The cache holds recording
plaintext, so it is dropped on seal and never written to disk.

**`GET .../keystrokes`** returns the `.rdp-rec` version-4 keystroke
transcript from BastionVault's index. Redacted runs come back withheld —
`text: null` plus their `reason` and `n` character count — and nothing in the
stack reconstructs one. The response's `state` distinguishes `not-indexed`,
`indexed`, `not-enabled` (keystroke recording was off for that session),
`digest-mismatch` and `failed`; **`not-enabled` is not a statement that
nothing was typed.** Emits `recording.transcript.accessed`, a separate audit
event from `recording.replayed`.

**`POST .../keystrokes/index`** — `{"recording_id": "rec_…", "force": false}`.
An empty `recording_id` sweeps every `rdp-rec` recording with no current
transcript, batched: each one costs a full artifact fetch from its bastion,
because the bastion's blob endpoint serves whole files and honours no
`Range`. The artifact digest is verified against the sidecar's `sha256`
before anything is persisted. Also runs automatically on the recordings
poller's hourly tick.

**`POST .../keystroke-search`** — `{"query": "net user /add", "limit": 200}`.
A `Write` with the query in the **body**, deliberately: a keystroke query is
user-supplied text describing a secret-bearing corpus, and putting it in a
URL would place it in access logs, proxy logs and browser history. It is not
logged server-side either — `recording.transcript.searched` records the
query's *length* and the hit/scanned/unindexed counts, never its content.

Matching is per keystroke run over non-redacted text, so a hit can never come
from a withheld run. The response reports `scanned` and `unindexed` alongside
`hits`: an empty result over a partly-unindexed corpus is not a negative
finding. Each hit carries `t_ms`, the run's first-keystroke offset, so a
player can seek there.

Namespace scoping matches the recordings list: in a non-root namespace only
recordings whose `target_host` matches a resource that namespace owns are
searchable, applied before any transcript is opened.

Format reference: [docs/rustion-integration.md](rustion-integration.md) §5.2.

### Asset Groups (resource bundles)

Asset groups bundle resources and KV secrets under a single name so
operators can share, scope, or filter on the bundle.

~~~
LIST   /v1/resource-group/groups
GET    /v1/resource-group/groups/{name}
PUT    /v1/resource-group/groups/{name}
DELETE /v1/resource-group/groups/{name}
GET    /v1/resource-group/groups/{name}/history
GET    /v1/resource-group/by-resource/{name}
GET    /v1/resource-group/by-secret/{b64url_path}
PUT    /v1/resource-group/reindex
~~~

`PUT /v1/resource-group/reindex` rebuilds both reverse indexes
from primary records — recovery path for torn writes.

### SSH Login Brokering Policy

Four-tier `login_class` policy (`shared-credential` | `brokered`) on the
`ssh-broker/` logical mount. Pinning a resource / type / asset-group to
`brokered` forbids storing a static SSH credential on it and forces every
SSH login through the SSH engine. Resolution is most-restrictive-wins; a
locked upstream tier returns `403 login_class_locked`. See
[`docs/ssh-login-brokering.md`](ssh-login-brokering.md).

~~~
GET    /v2/ssh-broker/policy/global                 # login_class_default + login_class_lock (root-gated)
PUT    /v2/ssh-broker/policy/global
GET    /v2/ssh-broker/policy/type/{type}            # login_class + lock
PUT    /v2/ssh-broker/policy/type/{type}
DELETE /v2/ssh-broker/policy/type/{type}
GET    /v2/ssh-broker/policy/asset-group/{id}       # login_class + priority + lock
PUT    /v2/ssh-broker/policy/asset-group/{id}
DELETE /v2/ssh-broker/policy/asset-group/{id}
GET    /v2/ssh-broker/policy/resource/{id}          # login_class (writable when no upstream tier is locked)
PUT    /v2/ssh-broker/policy/resource/{id}
DELETE /v2/ssh-broker/policy/resource/{id}
POST   /v2/ssh-broker/policy/effective              # resolve effective class for {resource_id, resource_type, asset_group_ids}
~~~

Attaching a static SSH credential (`private_key` / `password`) to a
brokered resource returns `409 brokered_resource_no_static_credential`.
CLI: `bvault ssh-broker policy {get,set}`.

### RDP Clipboard Policy and Audit

Server half of [RDP clipboard redirection](../features/rdp-clipboard-redirection.md)
§6 and §8 (T35).

**Clipboard ceilings on the Rustion policy tiers.** Two optional knobs on
every tier document of the four-tier transport policy, alongside
`transport` / `recording` / `lock`:

~~~
GET|PUT /v2/rustion/policy/global                 # + clipboard, clipboard_files
GET|PUT /v2/rustion/policy/type/{type}
GET|PUT /v2/rustion/policy/asset-group/{id}
GET|PUT /v2/rustion/policy/resource/{id}          # 403 when it would widen a locked upstream ceiling
POST    /v2/rustion/policy/effective              # + clipboard, clipboard_source, clipboard_files,
                                                  #   clipboard_files_source, clipboard_locked_by,
                                                  #   clipboard_lock_conflict
~~~

Values are exactly `off` | `host-to-session` | `session-to-host` |
`bidirectional`; anything else is `400`. On a write, a key that is **absent
leaves the stored value unchanged** (so a client that predates the knob
cannot erase a pin by omission) and `""` clears it. Tiers combine by
intersection — the most restrictive wins — and an unset knob constrains
nothing, so `policy/effective` reports `bidirectional` with source
`default` when no tier sets one. The desktop host intersects the connection
profile's `rdp_clipboard` / `rdp_clipboard_files` with the result; no
profile value widens past it. A clipboard conflict with a locked tier is
reported as `clipboard_lock_conflict`, never as `lock_violation`, and does
not refuse a session. These are BastionVault-only fields on existing
BastionVault-only paths — no route or operation was added to `v1`.

**`POST /v2/resources/v2/connect/clipboard/audit`** — the vault-side audit
row for a batch of clipboard transfers; the request pipeline writes it to
every audit device.

~~~json
{
  "resource": "srv1",
  "profile_id": "p_rdp",
  "session": "rdp_0123abcd",
  "seq": 3,
  "final": false,
  "transfers": { "session-to-host.text.ok": [120, 33], "host-to-session.file.oversize": [268435457] },
  "overflow":  { "session-to-host.image.ok": { "count": 40, "bytes": 9000000 } }
}
~~~

Keys are `<direction>.<kind>.<outcome>` from a closed vocabulary —
direction `host-to-session` | `session-to-host`, kind `text` | `image` |
`file`, outcome `ok` | `oversize` | `refused` | `malformed` | `error` — and
every value is a byte count (`transfers`: one per transfer) or a
`{count, bytes}` pair (`overflow`: transfers folded in by the host's rate
limit). There is no field for content or file names, and a body that tries
to carry one is refused. At most 256 entries per batch; only a `final`
batch may be empty; `session` is `[A-Za-z0-9_-]{1,64}`. The caller needs
`connect` (or `read` / `root`, ownership, or a share) on the resource and
the profile must be an RDP profile (`400` otherwise, `404` for an unknown
profile). The endpoint is granted by every baseline policy (`default`,
`shared-access` and the namespace baselines); the host withdraws the
session's clipboard if a batch is refused. Response:
`{ "accepted": <transfers>, "seq": <seq> }`.

### Audit Trail, Retention and Dashboard Statistics

See [`features/audit-retention-and-dashboard-stats.md`](../features/audit-retention-and-dashboard-stats.md).

**Unified audit trail** — `GET /v2/sys/audit/events` (also `/v1`), sudo-gated.
Newest-first rows from every replicated audit store and change history.

~~~
GET /v2/sys/audit/events?from=<RFC3339>&to=<RFC3339>&limit=<n>
~~~

| Parameter | Default | Meaning |
|---|---|---|
| `from` | 24 hours before `to` (or before now) | Lower bound. Without it the read is the last 24 hours, never the whole history. |
| `to` | none | Upper bound. |
| `limit` | `500` | Maximum rows returned. |

A bound that is not RFC3339, or a `limit` that is not a positive integer, is a
400. The parameters may also travel in the request body (body wins). The
response carries the bound that was applied, and names any source that could
not be read (its events are missing, so the trail is incomplete):

~~~json
{ "events": [ { "ts": "...", "user": "...", "op": "read", "category": "access", "target": "secret/data/x", "changed_fields": [], "summary": "" } ],
  "from": "2026-10-13T10:00:00+00:00",
  "failed_sources": [] }
~~~

**Retention** — `v2` only, sudo-gated (`sys/audit-retention` is in the system
backend's `root_paths`). Deployment-wide; replicated.

~~~
GET       /v2/sys/audit-retention    # effective setting, schedule, last run
POST|PUT  /v2/sys/audit-retention    # { "retention_days": 90 } and/or { "enabled": false }
~~~

- `retention_days`: integer, 1–36500 (default 365). `0`, negatives, fractions and
  larger values are refused with 400 — `0` is never "delete everything".
- `enabled`: `false` keeps every record forever.
- A write may carry either field; the other keeps its value. Changes apply from
  the next run.

Response:

~~~json
{
  "retention_days": 365, "enabled": true, "source": "default",
  "updated_at": "", "updated_by": "",
  "min_retention_days": 1, "max_retention_days": 36500,
  "schedule": "daily at 00:00 UTC", "next_run_at": "2026-10-15T00:00:00+00:00",
  "armed_at": "2026-10-14T09:12:03+00:00",
  "last_run": {
    "started_at": "...", "finished_at": "...", "cutoff": "...", "retention_days": 365,
    "outcome": "completed", "node_id": 1,
    "stores": [ { "store": "access-audit", "deleted": 1200, "remaining": 183132, "unrecognised": 0, "batches": 3,
                  "rule": "configured", "retention_days": 365, "cutoff": "..." } ]
  },
  "status_error": null,
  "stores": ["access-audit", "denial-audit", "login-audit", "user-audit", "share-history", "files-audit", "ssh-sign-audit", "ssh-ca-audit", "mcp-session-transcripts"],
  "store_rules": [ { "store": "access-audit", "rule": "configured", "retention_days": 365 },
                   { "store": "mcp-session-transcripts", "rule": "fixed", "retention_days": 30 } ]
}
~~~

Each store has its own rule (`store_rules`). Every audit store is
`configured`: it follows `retention_days` and is not pruned while `enabled` is
`false` (`retention_days` is then `null` in `store_rules`). The MCP session
transcripts (`mcp-session-transcripts`, see
[MCP Endpoints](#get-v2sysmcptranscripts)) are `fixed` at 30 days: pruned at
the first permitted daily run after 30 days whatever `retention_days` says —
including `enabled: false` and an unreadable setting — and never kept longer.

`source` is `default` until a value has been written. `outcome` is one of
`completed`, `partial` (a store failed; its `error` says why), `disabled` (no
audit record deleted; the `fixed` stores were still pruned and are the only
entries in `stores`), `failed` (no audit record deleted — e.g. the setting
could not be read; the `fixed` stores were still pruned), `refused` (nothing
deleted in any store — this node's clock is more than 2 days past the newest
record in the deployment, see below) or `interrupted` (the vault sealed
mid-run). Each `stores` entry carries its `rule`, `retention_days` and
`cutoff`; reports written by an older build lack them. The run happens once a day at 00:00 UTC on the cluster's Raft leader
(or the single node); a node that was down at midnight runs once when it comes
back. After an install or upgrade the first run is the first 00:00 UTC at least
24 hours after the leader first starts the new version (`next_run_at` shows
it) — on the default that run is destructive, see
[configuration](configuration.md#audit-retention-runtime-setting).

**Clock check.** The cutoff is the runner's clock minus the retention, so a
clock that jumped ahead would delete records early. Before deleting, the run
compares its clock with the newest record in any pruned store; if it is more
than 2 days ahead, it deletes nothing and reports `refused`. In a live
deployment the access, denial and login stores are written continuously, so
the gap is minutes; a deployment idle for more than 2 days simply waits for
new records (nothing is growing meanwhile).

**Dashboard summary** — `GET /v2/sys/dashboard/summary` (also `/v1`), readable
by every authenticated token. Mount, policy and entity counts are live and
scoped to the caller's ACL and namespace. The deployment-wide audit statistics
come from a record the cluster leader recomputes every 10 minutes, in two
tiers:

- `audit_24h`, `attention` and the `audit_stats` freshness fields: a caller
  holding `read`, `sudo` or root on `sys/audit/events` (unchanged).
- `audit_stats.recent` and `audit_stats.histogram_24h`: exactly what
  `sys/audit/events` itself requires — `read` **and** `sudo`, or root. They
  are omitted otherwise.

~~~json
{
  "version": "1", "namespace": "",
  "seal": { "sealed": false, "initialized": true },
  "counts": { "secret_mounts": 3, "auth_mounts": 2, "policies": 7, "entities": 11 },
  "audit_24h": { "total": 5120, "denied": 14, "write_failures": 0 },
  "attention": { "failed_logins_1h": 2 },
  "audit_stats": {
    "state": "ready", "version": 1,
    "computed_at": "2026-10-14T10:00:00+00:00", "age_secs": 140, "stale": false,
    "window_start": "2026-10-13T10:00:00+00:00",
    "histogram_24h": [210, 198, 175, 160, 150, 149, 180, 260, 340, 410, 420, 395,
                      380, 400, 415, 390, 350, 300, 260, 230, 220, 215, 205, 190],
    "histogram_bucket_secs": 3600,
    "recent": [ { "ts": "...", "user": "alice", "op": "read", "category": "access", "target": "secret/data/x", "changed_fields": [], "summary": "" } ],
    "partial": false, "failed_sources": [],
    "refresh_interval_secs": 600
  }
}
~~~

Until the first computation (or when the stored record has an unknown version
or cannot be read) `audit_stats` is `{ "state": "pending", "reason":
"not_computed" | "unsupported_version" | "unreadable" | "storage_error" }` and
`audit_24h` / `attention` are omitted, not zeroed. `stale` is `true` when the
record is 30 minutes old or more. `partial` is `true` when an audit source
could not be read during the computation (`failed_sources` names them); the
numbers are then a lower bound. `recent` holds the newest 20 rows of the last
24 hours, looking back up to 7 days when the day has fewer. `write_failures` is
the serving node's live counter. A caller without audit visibility gets none of
`audit_24h`, `attention` or `audit_stats`.

### DoS / Abuse Protection

IP-based request-abuse guard. Requests are counted per client IP over a sliding
window; an IP that exceeds `max_requests` (or the stricter `auth_max_requests`
on login paths) is temporarily banned for `ban_secs` and receives
`429 Too Many Requests` with a `Retry-After` header. Health, seal-status, and
metrics endpoints are exempt. The client IP honors `BASTIONVAULT_TRUSTED_PROXIES`
/ `X-Forwarded-For`. Thresholds and manual bans persist (HA-replicated);
enforcement is in-memory per node. All routes are root-gated. Any threshold set
to `0` disables that rule. See
[`features/dos-abuse-protection.md`](../features/dos-abuse-protection.md).

~~~
GET       /v2/sys/dos/config          # read thresholds
POST|PUT  /v2/sys/dos/config          # update thresholds (partial; only supplied keys change)
GET       /v2/sys/dos/stats           # live per-IP stats + active bans (this node)
POST|PUT  /v2/sys/dos/bans/{ip}       # manually ban an IP  { "ttl_secs": 3600, "reason": "..." }
DELETE    /v2/sys/dos/bans/{ip}       # unban an IP
~~~

Config fields: `enabled` (bool), `window_secs`, `max_requests`,
`auth_max_requests`, `ban_secs`, `refresh_secs`. An optional startup
`dos { ... }` config block seeds the initial values.

### Bulk metadata listings (`<list>-info`)

Every list-heavy view needs one summary per listed object. Reading them one at
a time is `1 + N` requests per page load — enough, on a mount holding a few
hundred objects, to cross the abuse guard's own ceiling above and ban the
caller. These endpoints return a **page of summaries** instead.

~~~
GET /v2/{mount}/certs-info                 # PKI: issued certificates
GET /v2/{mount}/csr-info                   # PKI: pending outgoing CSRs
GET /v2/{mount}/sign-request-info          # PKI: inbound sign-request queue
GET /v2/{mount}/roles-info                 # SSH: role configurations
GET /v2/{mount}/targets-info               # cert-lifecycle: targets + renewer state
GET /v2/auth/{mount}/users-info            # userpass: user records + FIDO2 key counts
GET /v2/sys/namespaces-info                # child namespaces + their records
~~~

All seven share one contract:

| Parameter | Meaning |
|---|---|
| `after` | Cursor: the `next` value from the previous page. Omit for the first. |
| `limit` | Page size. Default 100, capped at 500. |

~~~json
{
  "keys":      ["<name>", "..."],
  "records":   [ { /* one summary per key, same order */ } ],
  "total":     1200,
  "next":      "<cursor>",
  "truncated": true
}
~~~

- **`after` is a key, not an offset.** The next page starts strictly after the
  named key in lexicographic order, so creating or deleting an object between
  two requests can neither re-serve a row nor skip one. A cursor naming a
  since-deleted key still resumes in the right place.
- **`next` is empty on the last page**, and `truncated` mirrors that. A cursor
  past the end is an empty, non-truncated page — not an error.
- **These are reads**, so paging a listing stays available to a read-only
  policy, and each page is authorized exactly like the listing path it
  replaces. A summary is a projection of records the caller can already read
  individually; these endpoints grant nothing new.
- **Records are the same projection the single read returns**, minus large
  bodies: `certs-info` and `csr-info` omit PEMs, `sign-request-info` omits the
  CSR and certificate. Fetch the single object when you need those.
- `targets-info` nests the renewer state under `state` (both halves carry a
  `name`); `users-info` rows add `registered_keys` and `fido2_enabled`. A user
  record carries `username` in both the single read and the listing — the name
  is the storage key rather than a stored field, so the projection has to
  restate it or a bulk row could not name its principal.

Against a server that predates one of these routes the response is
`404 … path not supported`; clients fall back to the per-object reads. See
[`features/client-request-efficiency.md`](../features/client-request-efficiency.md).

### Cache coherence (`sys/cache/version`)

Change epochs for the mounts a client names, so it can drop stale cached
listings when *another* client writes instead of waiting out a local TTL.

~~~
GET /v2/sys/cache/version?topics=pki/,auth/userpass/
GET /v2/sys/cache/version?topics=pki/&watch=1      # long-poll (~25 s)
~~~

~~~json
{ "version": 412, "topics": { "pki/": 17, "auth/userpass/": 3 }, "coarse": false }
~~~

- `version` is a monotonic aggregate bumped by **any** change on the node, and
  is also the response `ETag`. Send it back as `If-None-Match` and a quiet
  vault answers `304` — a poll costs a header exchange, not a body.
- `topics` maps mount path → epoch. An epoch that has **increased** since the
  client's last observation means that mount was written to.
- `watch=1` blocks until the aggregate changes or ~25 s elapses, then answers
  normally (or `304` on timeout).
- `coarse: true` means the server has more live topics than it will itemize.
  Treat a `version` bump as global and drop the whole cache.

Authorization and disclosure:

- **The caller must name its topics.** There is no enumeration — the endpoint
  will not list what mounts exist.
- **Each named topic is authorized** against the caller's own capabilities for
  that mount. A topic the caller may not read is **omitted** from `topics`,
  not reported as zero: an epoch is an activity signal, and an absent key
  makes no claim about the mount. At most 64 topics per request.
- Epochs are scoped to the namespace the request is made in (the
  `X-BastionVault-Namespace` header), so a snapshot never reveals activity in
  another tenant.

Operational notes:

- Epochs are **in-memory and per node**, like the abuse guard's counters:
  persisting a counter on every write would double the vault's write cost.
  In an HA cluster two clients pinned to different nodes will not invalidate
  each other, so a client cache must keep a TTL as its backstop.
- Counters **reset on restart**, so treat only an *increase* as evidence of a
  write. Acting on a decrease would clear caches on every failover.
- A **login does not bump** its auth mount, even though it touches the stored
  user record: waking every watcher on every sign-in would cost more than the
  staleness it prevents. A `failed_login_count` in an admin listing can
  therefore lag by one cache TTL.

See [`features/client-request-efficiency.md`](../features/client-request-efficiency.md).

### Metrics

~~~
GET /metrics                # Prometheus text exposition (not /v1-prefixed)
~~~

Authorization-gated. Served when the socket peer is cluster-local (loopback or
a configured cluster node — the same predicate as `sys/cluster-status`), when
the client IP is in `metrics { allow_unauthenticated_cidrs = [...] }`, or when
the request carries a token with `read` on the ACL path `sys/metrics`.
Otherwise `403`. A sealed node cannot validate tokens, so only the IP
allowances work across a seal (`503` is returned to a token-bearing scrape in
that state). See
[Metrics Access](configuration.md#metrics-access-optional).

~~~bash
curl -H "X-Vault-Token: $TOKEN" https://127.0.0.1:8200/metrics
~~~

## Secret Operations

All secret operations go through logical paths mounted by secrets engines.

### Read a Secret

~~~
GET /v1/{mount}/{path}
~~~

Example:

~~~bash
curl -H "X-Vault-Token: $TOKEN" https://127.0.0.1:8200/v1/secret/my-app
~~~

Response:

~~~json
{
  "renewable": false,
  "lease_id": "",
  "lease_duration": 3600,
  "auth": null,
  "data": {
    "username": "admin",
    "password": "s3cret"
  }
}
~~~

### Write a Secret

~~~
POST /v1/{mount}/{path}
~~~

Example:

~~~bash
curl -H "X-Vault-Token: $TOKEN" \
  --request POST \
  --data '{"username": "admin", "password": "s3cret"}' \
  https://127.0.0.1:8200/v1/secret/my-app
~~~

### Delete a Secret

~~~
DELETE /v1/{mount}/{path}
~~~

### List Secrets

~~~
LIST /v1/{mount}/{path}
~~~

Or with `GET` and a query parameter:

~~~
GET /v1/{mount}/{path}?list=true
~~~

### PKI role: managed private keys

A PKI role can keep the private key of every certificate `issue` generates.
The role path is served on both `/v1` and `/v2`; use `/v2` for new
integrations.

~~~
POST /v2/{mount}/roles/{name}      {"manage_private_key": true, ...}
POST /v2/{mount}/issue/{name}      {"common_name": "..."}
POST /v2/{mount}/cert/{serial}/export  {"format": "pem", "include_private_key": true}
~~~

- `manage_private_key` (bool, default `false`): every key `issue/{name}`
  generates is stored in the mount's managed key store (`LIST
  {mount}/keys`), barrier-sealed, `exportable = true`, named
  `<role>-<serial>`, and bound to the certificate (`key_id` on the
  certificate record). The issue response carries `key_id` and still
  returns `private_key` as before.
- Refused with `400` when combined with `no_store = true`: the key is bound
  to the stored certificate record, which `no_store` never writes.
- A `key_ref`-pinned issuance is unaffected (that key is already managed).
  `sign/{name}`, `sign-verbatim` and ACME are CSR-based — the caller holds
  the key — so the option does not apply there.
- The kept key can be exported with the certificate (PEM or PKCS#12, POST
  only) and cannot be deleted while the certificate is bound; revoking the
  certificate drops the binding.

### PKI issuer renewal

Re-issue an issuer's CA certificate for the **same key and subject** with a
fresh validity, e.g. a root that is about to expire or already has. `v2` only.

~~~
POST /v2/{mount}/issuer/{ref}/renew     {"ttl": "87600h"}
GET  /v2/{mount}/issuer/{ref}/history
~~~

- `ttl` (optional): validity from now. Empty keeps the current certificate's
  `notAfter - notBefore`. `notBefore` is backdated 30 s, as on generation.
- Kept byte for byte: subject, public key and every extension (BasicConstraints,
  KeyUsage, SKI, name constraints, policies, ...). New: serial, validity,
  signature. Certificates the issuer already signed chain to the new one.
- Unchanged: issuer id, name, default pointer, usages, managed key
  (`key_id`), `ca_kind`. The key never leaves the managed-key store.
- A **self-signed** issuer is re-signed with its own key. Any other issuer is
  re-signed by its parent when that parent is a key-holding issuer on the same
  mount: issuer and AKI follow the parent, the validity is clamped to the
  parent's `notAfter` (`ttl_clamped: true`), and the parent needs the
  `issuing-certificates` usage and a `pathLenConstraint` other than 0.
- Refused, with the reason: a key-less (trust/chain-only) issuer (`400`); a
  parent that is not on this mount or is key-less here (`409`, renew at that
  CA); an expired parent (`400`).
- Response: `issuer_id`, `issuer_name`, `certificate`, `serial_number`,
  `not_before`, `not_after`, `previous_serial_number`, `previous_not_after`,
  `signed_by` (`"self"` or the parent issuer's name), `signed_by_issuer_id`,
  `ttl_clamped`.
- `history` lists the replaced certificates, oldest first:
  `{"certificates": [{"serial_number", "not_after", "replaced_at",
  "replaced_by_serial_number", "certificate"}]}`. Re-importing a replaced
  certificate through `config/ca` matches the existing issuer instead of
  adding a second one.
- ACL: renewal is its own path, so `update` on `{mount}/issuer/+` (rename,
  usages) does not grant it. The built-in `pki-full` template covers it
  through `pki/*`; `pki-read` grants neither path.

## Authentication Endpoints

### Token Login

Tokens are passed via the `X-Vault-Token` header or a `token` cookie on every request.

### Userpass Login

~~~
POST /v1/auth/{mount}/login/{username}
~~~

Request body:

~~~json
{
  "password": "my-password",
  "totp_code": "123456"
}
~~~

`totp_code` is required only when TOTP MFA is enabled globally
(`config/mfa`) **and** for this user (`totp_mfa_enabled`). A disabled account,
a locked-out account, or a missing/invalid TOTP code is rejected with a
generic error and no `auth` block. A failed TOTP code counts toward the
lockout threshold just like a bad password.

Response includes an `auth` block with the client token:

~~~json
{
  "auth": {
    "client_token": "s.xxxxxxxx",
    "policies": ["default"],
    "lease_duration": 3600,
    "renewable": true
  }
}
~~~

### Userpass User Management

**Create/update a user**

~~~
POST /v1/auth/{mount}/users/{username}
~~~

~~~json
{
  "password": "new-password",
  "policies": "default,admin",
  "disabled": false,
  "totp_mfa_enabled": true,
  "totp_key": "alice-mfa",
  "totp_mount": "totp/"
}
~~~

Account-security fields (all optional; a field omitted from the request is
left unchanged):

- `disabled` — when `true`, all authentication for this user is refused.
- `totp_mfa_enabled` — require a TOTP second factor (a `totp_key` must be set).
- `totp_key` — TOTP key name to validate against.
- `totp_mount` — TOTP engine mount (default: the global `config/mfa`
  `default_mount`, i.e. `totp/`).

**Read a user**

~~~
GET /v1/auth/{mount}/users/{username}
~~~

The response includes `disabled`, `totp_mfa_enabled`, `totp_mount`,
`totp_key`, `failed_login_count`, and a computed `locked` boolean.
`password_hash` and FIDO2 credential material are never returned.

**Unlock a user** (clear a lockout + reset the failed-attempt counter)

~~~
POST /v1/auth/{mount}/users/{username}/unlock
~~~

**Delete a user**

~~~
DELETE /v1/auth/{mount}/users/{username}
~~~

**List users**

~~~
LIST /v1/auth/{mount}/users
~~~

### Userpass Account Security Configuration

**Account lockout** (temporary lock after repeated failed passwords):

~~~
GET  /v1/auth/{mount}/config/lockout
POST /v1/auth/{mount}/config/lockout
~~~

~~~json
{
  "enabled": true,
  "max_failed_attempts": 5,
  "lockout_duration_secs": 900
}
~~~

Enabled by default. `max_failed_attempts: 0` disables locking even when
`enabled`.

**TOTP MFA** (global master switch + default engine mount):

~~~
GET  /v1/auth/{mount}/config/mfa
POST /v1/auth/{mount}/config/mfa
~~~

~~~json
{
  "enabled": false,
  "default_mount": "totp/"
}
~~~

Opt-in (`enabled: false` by default). When off, per-user `totp_mfa_enabled`
flags are not enforced.

### AppID Login

~~~
POST /v1/auth/{mount}/login
~~~

~~~json
{
  "role_id": "xxxx-xxxx",
  "secret_id": "yyyy-yyyy"
}
~~~

### AppID Management

**Create/update a role**

~~~
POST /v1/auth/{mount}/role/{role_name}
~~~

**Read a role**

~~~
GET /v1/auth/{mount}/role/{role_name}
~~~

**Get role ID**

~~~
GET /v1/auth/{mount}/role/{role_name}/role-id
~~~

**Generate secret ID**

~~~
POST /v1/auth/{mount}/role/{role_name}/secret-id
~~~

## MCP Endpoints

MCP Access (see [`mcp.md`](mcp.md)). All of these are `v2` only and require the
`mcp { enabled = true }` server block. TLS is required (plaintext only on a
loopback-only listener with `allow_plaintext_loopback`).

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/v2/mcp` | MCP-bound bearer | The MCP JSON-RPC endpoint (`server/discover`, `tools/list`, `tools/call`) |
| `GET` | `/.well-known/oauth-protected-resource/v2/mcp` | none | RFC 9728 metadata (minimal) |
| `POST` | `/v2/mcp/token` | login token | Exchange for an MCP-bound token |
| `GET`/`POST` | `/v2/sys/mcp/config` | `sudo` | Runtime limits, `catalogue_pin`, and the brokered-session runtime switch and destination allow-list |
| `LIST` | `/v2/sys/mcp/apps` | ACL | List MCP apps |
| `GET`/`POST`/`DELETE` | `/v2/sys/mcp/apps/{name}` | ACL | App record; `DELETE` revokes its tokens. A brokered-session tool in `tool_allowlist` is refused, permanently |
| `POST`/`DELETE` | `/v2/sys/mcp/apps/{name}/machine-waiver` | `sudo` | Grant (`reason`, `expires_in_days` 1-90) or revoke a machine-identity waiver; revoking also revokes the tokens minted under it |
| `LIST` | `/v2/sys/mcp/tokens` | ACL | Active MCP-bound tokens (`kind` is `app` or `pairing`) |
| `DELETE` | `/v2/sys/mcp/tokens/{accessor}` | ACL | Revoke one token |
| `DELETE` | `/v2/sys/mcp/pairings/{id}` | ACL | Revoke every token minted for one local pairing |
| `LIST` (or `GET`) | `/v2/sys/mcp/transcripts` | `list` + `sudo` | Brokered-session transcript ids, newest first |
| `GET` | `/v2/sys/mcp/transcripts/{id}` | `read` + `sudo` | One brokered-session transcript |

### `POST /v2/mcp/token`

Send the login token in `X-BastionVault-Token`, `X-Vault-Token` or
`Authorization: Bearer`. Exactly one of `app` and `pairing` is required.

```json
{ "app": "ci-secrets-reader", "policies": "ai-reader", "ttl_secs": 3600, "catalogue_hash": "<hash>" }
```

```json
{ "pairing": { "id": "<[a-z0-9-]{1,64}>", "client_name": "claude-desktop", "client_version": "1.0",
               "tool_allowlist": ["bv_kv_read_metadata"], "path_scope": ["secret/metadata/ai/*"],
               "reveal_allowed": false, "destructive_allowed": false, "ttl_secs": 28800,
               "connect_allowed": false, "confirm_connect": true } }
```

- **App mode** requires the caller to be the app's AppID login, carrying a
  machine identity or an active waiver (`403 mcp_machine_identity_required`).
  An app record whose `tool_allowlist` names a brokered-session tool (one
  written before `sys/mcp/apps` refused them) cannot be exchanged
  (`400 mcp_connect_requires_local_operator`): network-mode apps never open
  sessions.
- **Pairing mode** requires an operator session: an entity- or
  username-bound login, never AppRole, machine, root or MCP-bound
  (`403 mcp_pairing_requires_operator_session`).
- **Brokered sessions** ([spec](../features/mcp-brokered-sessions.md) §9),
  pairing mode only. `connect_allowed` and `confirm_connect` are optional
  booleans, refused when present with any other type.
  - `confirm_connect` can never be `false`: an explicit `false` is refused,
    with or without `connect_allowed`. Every pairing token minted carries
    `confirm_connect = true`.
  - `connect_allowed: true` requires `confirm_connect: true` in the body;
    absent is refused, not defaulted.
  - A session tool (`bv_resource_ssh_exec`, `bv_resource_web_fetch`,
    `bv_resource_rdp_act`) in `tool_allowlist` requires `connect_allowed`.
  - `connect_allowed` may be granted together with `reveal_allowed`. Such a
    token can read secret values **and** open sessions to servers; the
    per-call operator confirmation is the control for that combination.
  - The token records the operator (entity id, username, login mount and
    namespace) from the caller's own login, for audit and for binding an
    operator's MFA step-up to one call. It is never used for authorization.
- The token's policies are the caller's, narrowed by `policies`, never wider.

Response: `{ "auth": { "client_token", "accessor", "policies", "lease_duration",
"metadata": { "mcp_kind", "mcp_name" } } }`. The token is refused by every
endpoint except `POST /v2/mcp`.

### `POST /v2/mcp`

Bearer token in `Authorization`. The body is one JSON-RPC request (no batches).
Refusals: `401` missing or unknown token, `403` a token that is not MCP-bound,
expired, or whose waiver ended, `413` over `max_request_bytes`, `503`
`mcp_requires_tls` or `mcp_hybrid_kex_unverifiable`. Tool errors are JSON-RPC
errors whose `data.code` is one of `mcp_tool_not_allowed`,
`mcp_path_out_of_scope`, `mcp_reveal_denied`, `mcp_destructive_denied`,
`mcp_invalid_argument`, `mcp_tool_timeout`, `mcp_connect_not_allowed` (a
session tool on a token without `connect_allowed` and `confirm_connect`) and
`mcp_connect_requires_local_operator` (a session tool on an app token,
always), plus the session handlers' codes listed under
[`resources/v2/connect/agent/ssh/exec`](#post-resourcesv2connectagentsshexec-mcp-only)
and [`resources/v2/connect/agent/web/fetch`](#post-resourcesv2connectagentwebfetch-mcp-only).

`params._meta` may carry, besides `io.modelcontextprotocol/*`, the local
gatekeeper's `io.bastionvault/confirmation` (the operator approved this call)
and `io.bastionvault/connect_ticket` (the operator's MFA ticket for this
session call, handed only to the session handler). The gatekeeper removes
both from whatever the client sent before adding its own.

The catalogue has two session tools, `bv_resource_ssh_exec` and
`bv_resource_web_fetch`, which report `openWorldHint: true`; every other tool
reports `false`. **This retracts the earlier statement that no tool opens a
network connection.** A session tool needs the token's `connect_allowed`, is
never gated on `destructive_allowed` (its `destructiveHint` is advice to the
client), is never in a pairing's default tool list (the web fetch, read-only
by HTTP semantics, included), and its call timeout is
`mcp.brokered_sessions.call_timeout_secs` (plus 10 s for the handler to
answer) instead of `mcp.tool_timeout_secs`. Arguments other than a tool's own
are refused (`mcp_invalid_argument`):

- `bv_resource_ssh_exec`: `resource`, `profile` (required), `command` and an
  optional `timeout_secs`. A command with a control, bidi, zero-width, tag,
  line-separator or other invisible character is refused, never cleaned.
- `bv_resource_web_fetch`: `resource`, `profile`, `path` (required), `method`
  (`GET`, the default, or `HEAD`) and an optional `timeout_secs`. The path is
  origin-relative: it starts with `/` but not `//`, is at most 2048 bytes of
  RFC 3986 characters (every `%` a valid escape), has no fragment, no `..`
  segment after percent-decoding (repeatedly, and split on `/` and `\`; `..;`
  counts), and nothing a URL parser would rewrite (a `.` segment, a `'` in the
  query). Refused, never cleaned or normalized.

A session result is wrapped: `structuredContent.untrusted` names the source
(`{"source": "resource", "protocol": "ssh" | "web", "resource", "profile"}`)
and `content[0].text` starts with a constant preamble saying the output is data
from a remote system. A shaped result over 1 MiB + 64 KiB is refused
(`mcp_result_too_large`).

The catalogue hash is
`2ef9b8149ea89aa2d509d204988414450bd12658223299e7ee77eb8a48bf5262`
(`bv_resource_web_fetch` appended to the 0.44.40 catalogue,
`3f24b819…bd173`); a `catalogue_pin` set to an earlier value must be updated.

**Audit.** Every request a `tools/call` routes is recorded with an `mcp`
block beside `request.data` (`request.mcp`), in the clear:

```json
"mcp": { "kind": "pairing", "name": "<pairing id or app name>", "client_name": "claude-code",
         "client_version": "2.1", "transport": "http", "tool": "bv_kv_list",
         "catalogue_hash": "<hash>", "args_hash": "<BLAKE3 hex of the call's arguments>",
         "reveal_requested": false, "reveal_granted": false, "destructive": false,
         "confirmed_by_operator": true, "operator_confirmation": "asserted-by-local-host",
         "decision": "allowed", "tls_kx_group": null, "waived": false, "peer_uid": null,
         "peer_pid": null, "otel_traceparent": null, "otel_tracestate": null }
```

`transport` is what the vault sees: `http` (`bv-server`'s route) or
`in-process` (an embedded vault). `decision` is `allowed` because the block is
written only on a routed request; the ACL outcome underneath is the entry's
own. `confirmed_by_operator` is the local gatekeeper's assertion, sent as
`_meta["io.bastionvault/confirmation"] = {"by": "operator", "at": <unix>,
"mfa": <bool>}`; the vault cannot observe the confirmation, so it records
`operator_confirmation: "asserted-by-local-host"` beside it. The arguments
appear only as `args_hash` (and HMAC'd in the body). A session tool the
dispatcher refuses is recorded as a `connect.agent.refused` event (below).

**Brokered-session events** ([spec](../features/mcp-brokered-sessions.md)
§10). Written as audit entries with `"type": "event"`, the event name in
`request.path`, `request.operation` `"event"` and the fields in the clear in
`request.data` (and as one line on the security log, with or without an audit
device). No event carries credential material, certificates, tickets, command
text, URL paths, page text or images; a command appears only as
`command_hmac` (`hmac:<hex>` under the audit HMAC key).

| Event | Fields |
|---|---|
| `connect.agent.refused` | `reason` (the `data.code`), `tool`, `protocol`, `resource`, `profile_id` (the call's arguments, cut at 128 characters), `operator`, `pairing_id`, `client_name` |
| `connect.agent.ssh.exec` | `session_id`, `operator`, `pairing_id`, `client_name`, `binding_reveal_allowed`, `resource`, `profile_id`, `target`, `host_key_fingerprint`, `login`, `cert_serial`, `mfa_method`, `command_hmac`, `command_bytes`, `exit_status`, `exit_signal`, `timed_out`, `stdout_bytes`, `stderr_bytes`, `truncated`, `credential_echo_redacted`, `duration_ms`, `transcript_id`, `operator_confirmation` |
| `connect.agent.aborted` | `session_id`, `cause` (`token_revoked`, `kill_switch`, `timeout`, `executor_error`), `protocol`, `resource`, `profile_id`, `operator`, `pairing_id` |
| `mcp.transcript.accessed` | `operation` (`read` or `list`), `transcript_id`, `listed`, `found` |

`connect.agent.refused` comes from the dispatcher (refused before routing)
or from the session handler (refused after routing, before anything is
dialed, and on a host-key mismatch); the handler's `reason` is its error code,
or `permission_denied` when the `connect` gate refused. A session that dialed
writes one `connect.agent.ssh.exec`, and also `connect.agent.aborted` when it
was cut short (`timeout`, `token_revoked`, `kill_switch`) or failed after
dialing (`executor_error`: connection refused, login rejected).

Every string a tool returns has C0/C1 controls (except newline and tab),
ANSI CSI/OSC sequences, Unicode bidi controls (including LRM, RLM and ALM),
zero-width characters, tag characters (U+E0000–U+E007F) and interlinear
annotation characters removed; U+2028 and U+2029 become newlines.

### `GET`/`POST /v2/sys/mcp/config`

Besides `default_ttl_secs`, `max_ttl_secs`, `waiver_max_days` and
`catalogue_pin`, two keys govern brokered sessions
([spec](../features/mcp-brokered-sessions.md) §11-12). Both read as off / not
set on a record written before they existed.

| Key | Type | Default | Meaning |
|---|---|---|---|
| `brokered_sessions_enabled` | bool (`"true"`/`"false"` accepted) | `false` | The runtime switch. Every session call also needs the server config's `mcp.brokered_sessions.enabled` and its protocol in `protocols` |
| `brokered_sessions_allowed_target_cidrs` | list of CIDRs, a comma-separated string, or `null` | `null` | The destination allow-list. `null` means the server config's `mcp.brokered_sessions.allowed_target_cidrs` applies, or the built-in `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]` when that sets none. A list **replaces** it; `[]` (or `""`) allows no destination |

Every entry must be `address/prefix` with no host bits set; otherwise the
write is refused (`400`) naming the entry, and nothing is stored. Loopback,
link-local (including `169.254.169.254`), multicast, unspecified, broadcast,
the vault's own listener addresses and the cluster node addresses are denied
whatever is listed: an entry overlapping one is accepted, has no effect there,
and earns a response `warnings` line. A change is logged to the security log
as `mcp.config.updated` with the old and new values. It applies to the next
dial on every node.

Reads (and the response to a write) also report what is in force, read-only —
a write ignores these keys:

| Key | Meaning |
|---|---|
| `brokered_sessions_effective_target_cidrs` | The destination allow-list in force |
| `brokered_sessions_target_cidrs_source` | Where it comes from: `runtime` (`brokered_sessions_allowed_target_cidrs` is set), `hcl` (the server config's `mcp.brokered_sessions.allowed_target_cidrs`, whether the file is HCL or JSON) or `default` |
| `brokered_sessions_server_enabled` | The server config's `mcp.brokered_sessions.enabled` |
| `brokered_sessions_server_protocols` | The server config's `mcp.brokered_sessions.protocols` |
| `brokered_sessions_always_denied` | The classes no list can re-allow: `loopback`, `link-local`, `multicast`, `unspecified`, `broadcast`, `vault-listener`, `cluster-node` |

### `GET /v2/sys/mcp/transcripts`

`LIST` (or `GET`) needs `list` **and** `sudo` on `sys/mcp/transcripts`; `GET
/v2/sys/mcp/transcripts/{id}` needs `read` **and** `sudo` on
`sys/mcp/transcripts/*` ([spec](../features/mcp-brokered-sessions.md) §10). No
baseline policy grants them, and no MCP tool can reach them. There is no `v1`
form.

A transcript is what one brokered session ran and what came back: the command
verbatim and its output after the session's own credential was scrubbed (the
writer scrubs every text field again) and before model sanitization, so ANSI
bytes are kept. It may hold **other** secrets a command printed (`cat .env`):
treat it as sensitive as any secret on the hosts agents reach. Transcripts
are stored under the system view, barrier-encrypted, and deleted after a fixed
30 days by the audit-retention run (see
[Retention](#audit-trail-retention-and-dashboard-statistics)).

Every list and every read — found or not — emits `mcp.transcript.accessed`
before anything is returned; when an audit device is enabled and that entry
cannot be written, the request is refused.

~~~json
// LIST /v2/sys/mcp/transcripts — keys only, newest first; no record is decrypted
{ "keys": ["01760531123456789000-as_6f0c01"],
  "key_info": { "01760531123456789000-as_6f0c01": { "recorded_at": "2026-10-15T12:25:23.456789+00:00", "session_id": "as_6f0c01" } } }

// GET /v2/sys/mcp/transcripts/01760531123456789000-as_6f0c01
{ "id": "01760531123456789000-as_6f0c01", "recorded_at": "...", "version": 1, "protocol": "ssh",
  "summary": { "session_id": "as_6f0c01", "tool": "bv_resource_ssh_exec", "resource": "web-01",
               "profile_id": "p_agent", "operator": { "entity_id": "", "username": "felipe", "mount_path": "userpass/", "namespace": "" },
               "pairing_id": "pair-1", "client_name": "claude-code", "binding_reveal_allowed": false,
               "operator_confirmation": "asserted-by-local-host", "mfa_method": null,
               "started_at_ms": 1760531123000, "finished_at_ms": 1760531123812, "credential_echo_redacted": true },
  "body": { "protocol": "ssh", "command": "…", "target": "10.0.0.9:22", "host_key_fingerprint": "SHA256:…",
            "login": "password", "cert_serial": null, "exit_status": 0, "exit_signal": null,
            "timed_out": false, "aborted": null,
            "stdout": { "text": "…", "seen_bytes": 18234, "stored_truncated": false, "model_truncated_at": 65536, "binary": false },
            "stderr": { "text": "", "seen_bytes": 0, "stored_truncated": false, "model_truncated_at": null, "binary": false } } }
~~~

An id is `<20-digit nanoseconds>-<session id>` (`[a-z0-9_-]`, at most 64
characters); anything else is a `400`. An unknown id is a `404`. A stored
record that does not decode — an unknown `version`, a missing body chunk, a
length mismatch, malformed JSON — is a `500` naming why, never a partial
answer. The session handlers write them: `bv_resource_ssh_exec` (`protocol:
"ssh"`, above) and `bv_resource_web_fetch` (`protocol: "web"`): `method`,
`path` (with its query), `origin`, `target` (the first `ip:port` dialed),
`login`, `tls` (`platform`, `pinned-leaf`, `pinned-issuer`), `hops` (every
request: `origin`, `path` with its query, `status`, `answered_challenge`),
`status`, `content_type`, `body_bytes`, `body_truncated`, `text` (the
extracted page text, credential- and cookie-scrubbed, up to 1 MiB, with
`model_truncated_at`), `timed_out`, `aborted`, and `stopped` (the refusal
code that ended a fetch after it had dialed). A web transcript is written
for every fetch that sent a request.

### Resource opt-ins for brokered sessions

An agent session can reach a connection profile only when both levels opt in;
absent means deny at both, so existing types and profiles are unaffected.

- **Resource type:** `config/types[<type>].connect.agent_sessions_max`,
  `"allow"` or `"deny"`. `POST resources/config/types` refuses any other value
  (`422 agent_policy_invalid`).
- **Connection profile:** `agent_access`, `"allow"` or `"deny"`, on an entry of
  the resource record's `connection_profiles`. `POST resources/resources/{name}`
  vets every new or changed profile that carries the key: any other value is
  refused (`422 agent_policy_invalid`), and `"allow"` is refused unless the
  resource's type (in the effective saved type configuration) allows it
  (`403 mcp_session_profile_not_agent_enabled`) and the profile meets its
  protocol's static requirements:
  - **SSH:** an `ssh-engine` source in `ca` mode or a `secret` source
    (`403 mcp_session_login_class_unsupported` otherwise), and a
    `host_key_pin` in OpenSSH `SHA256:<base64>` form
    (`403 mcp_session_host_key_unpinned`);
  - **web:** `login_mode` `open` or `http-auth`
    (`403 mcp_web_login_mode_unsupported`), an `https://` `start_url` and no
    `allow_insecure_http` (`403 mcp_web_origin_refused`), and a `secret`
    source for `http-auth`;
  - **RDP:** a `secret` source.

  A profile that did not change is not re-vetted on write, so turning a type
  back to `deny` does not block unrelated edits to its resources; the
  session handler re-checks both levels at every call.

### `POST resources/v2/connect/agent/ssh/exec` (MCP only)

The route behind `bv_resource_ssh_exec`
([spec](../features/mcp-brokered-sessions.md) §5, §13). It is **internal to
MCP**: a request that the MCP dispatcher did not route for an MCP-bound token
is refused (`403 mcp_connect_not_allowed`), so it is not a general remote-exec
API. It is not in the `default` policy; the operator who pairs the assistant
must hold:

```hcl
path "resources/v2/connect/agent/ssh/exec" { capabilities = ["update"] }
path "resources/secrets/<resource>/*"      { capabilities = ["connect"] }
```

The second line is the connect gate on the resource. An MCP token carries no
entity, so only a policy grant passes it: ownership and shares never
authorize an agent.

Body (the dispatcher builds it from the tool's arguments): `resource`,
`profile_id`, `command`, optional `timeout_secs` (1 to
`mcp.brokered_sessions.call_timeout_secs`), and `connect_ticket` — the
operator's MFA ticket the local gatekeeper relayed in
`_meta["io.bastionvault/connect_ticket"]`, never taken from the tool's
arguments.

Checks, in order, each refusal a stable code and a `connect.agent.refused`
event; nothing is dialed and no credential is touched before the last one
passes:

| Step | Refusal |
|---|---|
| MCP-dispatched, binding with `connect_allowed` + `confirm_connect` | `mcp_connect_not_allowed` |
| The binding is a local pairing | `mcp_connect_requires_local_operator` |
| The gatekeeper's confirmation record (`_meta["io.bastionvault/confirmation"]`, `by: "operator"`) | `mcp_confirmation_required` |
| The command is valid (as the dispatcher checks it) | `mcp_invalid_argument` |
| Server config `mcp.brokered_sessions.enabled`, the runtime `brokered_sessions_enabled` | `mcp_brokered_sessions_disabled` |
| `ssh` in `mcp.brokered_sessions.protocols`; the build has the executor (cargo feature `mcp_sessions_ssh`) | `mcp_session_protocol_disabled` |
| The connect gate on `resources/secrets/<resource>/` | `403 permission denied` (`reason: permission_denied`) |
| Type `agent_sessions_max` and profile `agent_access` both `"allow"`; an SSH profile with a supported source and a host-key pin | `mcp_session_profile_not_agent_enabled`, `mcp_session_login_class_unsupported`, `mcp_session_host_key_unpinned` |
| An MFA-gated profile (`require_mfa`) carries the operator's ticket for this exact call, redeemed once | `mcp_session_mfa_required` (no ticket); `mcp_session_mfa_ticket_refused` (unknown, spent, expired, a human ticket, or bound to another operator, resource, profile, pairing, tool or arguments hash — the ticket is burnt); `mcp_session_mfa_unavailable` (the pairing's operator is not a userpass user, or signed in to another namespace than the call runs in) |
| No bastion route: a `rustion` profile, a `rustion-required` policy, or `rustion-preferred` with a bastion | `mcp_session_requires_bastion` |
| Rate (per pairing per minute) and concurrency (one per pairing, `max_concurrent` per node) | `mcp_rate_limited`, `mcp_session_busy` |
| Destination policy on every resolved address of the target | `mcp_session_destination_refused` |

The confirmation record and the ticket come from the local gatekeeper
(`bvault mcp serve`, the desktop app), which strips any `io.bastionvault/*`
key the MCP client sent and adds its own only after the operator approved the
call ([spec](../features/mcp-brokered-sessions.md) §3.1, §9). The vault audits
the confirmation as `operator_confirmation: "asserted-by-local-host"`. The
ticket it verifies itself: it must have been minted by
[`connect/mfa/verify` with `mcp_call`](#post-resourcesv2connectmfaverify-with-mcp_call)
for the binding's operator (`mount`, `principal` and `namespace` from the
token's operator record), this resource and profile, and
`{pairing_id, tool, args_hash}` of this pairing, this tool and the hash of
this call's `arguments` (`args_hash` in the `mcp` audit block). It is
redeemed before any credential is touched, and a successful redemption is
logged as `connect.mfa.authorized … mcp_call=true pairing_id=… tool=…`; the
`connect.agent.ssh.exec` event and the transcript carry `mfa_method`.

The target is the profile's `target_host`, else the resource's `ip_address`,
else its `hostname`, on the profile's `target_port` (default 22) — never a
value from the call. The name is resolved once; every address must pass the
policy and only checked addresses are dialed. The host key is checked against
`host_key_pin` before any authentication (`mcp_session_host_key_mismatch`,
audited as a refusal).

The credential is resolved or minted under the server's authority and used
only in the vault process:

- **`ssh-engine` (`ca` mode)**, preferred: an ephemeral Ed25519 key is
  signed per call by `<ssh_mount>/sign/<ssh_role>` for the profile's
  `username`, requesting `force-command=<the command>`, `source-address`
  when `mcp.brokered_sessions.ssh.cert_source_addresses` is set, and a 60 s
  validity. The signed certificate is checked before use; a role that drops
  `force-command` or `source-address`, adds any extension (its
  `default_extensions` must be empty), or signs for longer than 60 s is
  refused naming the role (`422 mcp_session_login_class_unsupported`).
- **`secret`**: the resource secret's `private_key` (with `passphrase`) or,
  failing that, its `password`; the login is the secret's `username`, else
  the profile's.

The vault's client opens one `session` channel, sends one `exec` with the
command and `EOF`, and never a PTY, shell, environment, X11, agent, subsystem
or forwarding request; it refuses every channel the target opens towards it.

Response `data` (wrapped by the dispatcher in the untrusted envelope):

```json
{ "session_id": "as_6f0c…", "exit_status": 0, "exit_signal": null, "timed_out": false,
  "stdout": "…", "stdout_bytes": 18234, "stdout_truncated": false,
  "stderr": "", "stderr_bytes": 0, "stderr_truncated": false,
  "binary_output": false, "credential_echo_redacted": false, "duration_ms": 812,
  "host_key_fingerprint": "SHA256:…", "login": "password" }
```

- stdout and stderr share `mcp.brokered_sessions.max_output_bytes`; past it up
  to 1 MiB more is read and discarded, then the channel is closed. The byte
  counts are what the target sent.
- `binary_output: true` omits both strings.
- The session's own password, passphrase and private-key body lines are
  replaced with `<redacted:credential>` in every encoding the vault produces;
  `credential_echo_redacted` says so.
- At the call timeout the command is sent `KILL` and `timed_out: true` is
  returned. A connection that cannot be set up within 10 s fails with
  `mcp_session_timeout`; a refused connection or login with
  `mcp_session_failed`.
- The session's token and the runtime switch are re-checked every second:
  revoking the pairing or its token, signing out, or turning
  `brokered_sessions_enabled` off ends a running session within two seconds
  (`409 mcp_session_aborted`).

Every session that ran is recorded in a transcript
([`v2/sys/mcp/transcripts`](#get-v2sysmcptranscripts)): the command, both
streams as captured (up to 1 MiB each, credential-scrubbed, not sanitized),
the exit status and the host key.

### `POST resources/v2/connect/agent/web/fetch` (MCP only)

The route behind `bv_resource_web_fetch`
([spec](../features/mcp-brokered-sessions.md) §6, §13): one `GET` or `HEAD` of
a web-application resource, fetched by the vault process with the profile's
credential, which never leaves it. Like the SSH route it is **internal to
MCP** (`403 mcp_connect_not_allowed` for any request the dispatcher did not
route) and not in the `default` policy:

```hcl
path "resources/v2/connect/agent/web/fetch" { capabilities = ["update"] }
path "resources/secrets/<resource>/*"       { capabilities = ["connect"] }
```

It is compiled only with the cargo feature `mcp_sessions_web` (off by
default); `web` must be in `mcp.brokered_sessions.protocols`.

Body (built by the dispatcher): `resource`, `profile_id`, `method` (`GET` |
`HEAD`), `path`, optional `timeout_secs`, and the relayed `connect_ticket`.
The checks are the SSH route's, in the same order and with the same codes,
with these differences:

| Step | Refusal |
|---|---|
| `method` and `path`, re-checked with the dispatcher's rules | `mcp_invalid_argument` |
| `web` listed; the build has the executor (`mcp_sessions_web`) | `mcp_session_protocol_disabled` |
| A web profile, opted in, `login_mode` `open` or `http-auth` (`form` and `sso` need a browser, which waits on proxy mode or Rustion browser isolation) | `mcp_session_profile_not_agent_enabled`, `mcp_web_login_mode_unsupported` |
| https only: an `https://` `start_url` and `allowed_origins`, no `allow_insecure_http` | `mcp_web_origin_refused` |
| `http-auth` uses a stored `secret` (username and password, through `credential_source.fields`) | `mcp_session_login_class_unsupported` |
| No bastion route: a `rustion` profile, `web.transport: rustion-isolated`, a Rustion policy | `mcp_session_requires_bastion` |
| Destination policy on every address of the start origin's host | `mcp_session_destination_refused` |

**What is fetched.** The URL is the origin of the profile's `web.start_url`
plus the confirmed path, byte for byte. Its host is resolved once, every
address is checked against the destination policy, and only checked addresses
are dialed (a name gets them as its only DNS answer; no proxy, the
environment's included).

**Redirects** (`301`, `302`, `303`, `307`, `308`) are followed by the vault,
at most 5, only to https origins the profile lists (`web.start_url`'s and
`web.allowed_origins`), each hop resolved once and checked against the
destination policy before anything is sent to it. A redirect elsewhere stops
the fetch with `mcp_web_origin_refused` (and a refused hop address with
`mcp_session_destination_refused`); the redirect target is never returned or
logged. More than 5 redirects stop with `mcp_session_failed`.

**TLS.** The platform's trust anchors (the operating system's store, read once
at the first fetch), then the profile's `web.tls_pin_sha256` with the desktop
app's Phase 4 rules — the same code, `bv_utils::tls_pin`: a pin only admits a
certificate the platform rejected; a leaf pin is accepted as is; an issuer pin
only for a presented CA the leaf verifies under for the host. There is no
trust on first use and no "accept anyway": a certificate the platform rejects
is refused with `mcp_web_tls_unpinned` when the profile pins nothing, and with
`mcp_web_tls_pin_mismatch` when no pin admits it. No request is sent over a
refused connection.

**The credential** (`http-auth`) is HTTP Basic, sent only in answer to a `401`
`Basic` challenge from the origin being fetched, at most once per (origin,
realm) in a call — never pre-emptively, never to Digest, NTLM or Negotiate.
A second `401` after an answer is the result (the target refused the
credential, or challenged again after a redirect); the vault does not
retry.

**Request headers** are fixed: `User-Agent: BastionVault-Agent/<major.minor>`,
`Accept`, `Accept-Encoding: identity`, and the call's own cookies — a cookie
the target sets during the call goes back to that same origin on the call's
next request, and the jar is dropped with the call. The agent supplies no
header.

Response `data` (wrapped by the dispatcher in the untrusted envelope):

```json
{ "session_id": "aw_6f0c…", "method": "GET", "status": 200, "content_type": "text/html; charset=utf-8",
  "final_origin": "https://grafana.internal", "final_path": "/api/health", "redirected": false,
  "body_text": "…", "body_bytes": 312, "truncated": false, "binary_output": false,
  "credential_echo_redacted": false, "duration_ms": 140, "login": "http-auth" }
```

- At most 2 MiB of the final response's body is read; past it the
  connection is dropped and `truncated` is set. `HEAD` reads none.
- `text/html` and `application/xhtml+xml` are reduced to text (html5ever's
  tokenizer): `script`, `style`, `noscript`, `template`, `svg`, `iframe` and
  comments are dropped, links kept as `text <href>`. JSON, XML and every
  `text/*` are returned as text. Anything else, no `Content-Type`, or a body
  that is mostly NUL or not UTF-8 is `binary_output: true` with no
  `body_text`.
- `body_text` is cut at `mcp.brokered_sessions.max_output_bytes` (default
  64 KiB, ceiling 256 KiB) and then ends with `[… truncated by the vault]`;
  `truncated` says so.
- The profile's password is replaced with `<redacted:credential>` in every
  encoding the vault produces (raw, percent- and form-encoded, JSON-escaped,
  HTML-escaped, and the Basic `user:password` base64), and so is every cookie
  value of 8 or more characters the target set during the call.
- Only `content_type` is returned of the response headers: never a cookie,
  `Set-Cookie`, `Authorization` or `Location`. `final_path` carries neither
  the query nor `;` path parameters.
- A fetch past the call timeout ends with `504 mcp_session_timeout`; one
  that cannot connect, or fails mid-response, with `502 mcp_session_failed`.
  Revocation and the runtime switch end a running fetch within two seconds
  (`409 mcp_session_aborted`), as for SSH.

Events: `connect.agent.web.fetch` for a fetch that answered (`method`,
`path_hmac` and `path_bytes` — never the path —, `origin`, `target`, `login`,
`tls`, `status`, `redirects`, `credential_sent`, `body_bytes`, `truncated`,
`binary_output`, `credential_echo_redacted`, `mfa_method`, `transcript_id`,
and the pairing, operator and confirmation fields the SSH event carries);
`connect.agent.refused` (protocol `web`) for every refusal, including the ones
after dialing (an off-list redirect, a refused hop, a refused certificate);
`connect.agent.aborted` for a timeout, a revocation or a failure. Every fetch
that sent a request is recorded in a transcript.

### `POST resources/v2/connect/mfa/verify` with `mcp_call`

The connect-time MFA verify (`resources/v2/connect/mfa/begin` reports whether
a profile is gated and which factors the caller holds; `verify` takes
`resource`, `profile_id`, `method` = `totp` | `fido2`, and `totp_code` or
`credential`) accepts one more, optional body field for the MCP gatekeeper
([spec](../features/mcp-brokered-sessions.md) §3.1):

```json
{ "resource": "web-01", "profile_id": "p_agent", "method": "totp", "totp_code": "123456",
  "mcp_call": { "pairing_id": "0f3c…", "tool": "bv_resource_ssh_exec", "args_hash": "<64 hex>" } }
```

(`tool` is `bv_resource_ssh_exec` or `bv_resource_web_fetch`.)

- With `mcp_call`, the ticket is bound to that one agent call, expires after
  **60 s** (a human ticket: 120 s), and is redeemable **only** on the agent
  route above. Without it, the ticket is a human one, redeemable only on the
  human Connect paths (`connect/authorize`, `connect/web/launch`, the
  Rustion open). Each side refuses — and burns — the other's ticket.
- `mcp_call` is read strictly, before the factor is checked: exactly
  `pairing_id` (`[a-z0-9-]{1,64}`), `tool` (a brokered-session tool) and
  `args_hash` (64 lowercase hex, `bv_mcp::dispatcher::args_hash` of the
  call's `arguments`); anything else is `400`. A non-object `mcp_call` is
  refused, never read as absent.
- Only the operator's own session can ask for one: an MCP-bound token never
  reaches this path (the MCP-origin gate) and is refused here too (`403`).
- The step-up is userpass-only. `begin` and `verify` refuse any other caller
  on a gated profile with a reason that starts `mfa_unavailable:` (as they do
  a userpass caller with no factor enrolled); the gatekeeper turns that into
  `mcp_session_mfa_unavailable` before it prompts anyone.
- The response is the same as without `mcp_call`: `connect_ticket`,
  `expires_at`, `method`, `resource`, `profile_id`. The gatekeeper keeps the
  ticket in memory and relays it with the call; it is never shown to the MCP
  client or the desktop window.

## Response Format

All API responses follow a consistent structure:

~~~json
{
  "request_id": "uuid",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": { },
  "auth": null,
  "warnings": null
}
~~~

## Authentication

Include a token with every request using one of:

- **Header**: `X-Vault-Token: s.my-token`
- **Cookie**: `Cookie: token=s.my-token`

A small, deliberate set of system endpoints answers without a token, because a
caller needs them before a token can exist: `/v1/sys/init`,
`/v1/sys/seal-status`, `/v1/sys/unseal`, `/v1/sys/health`, and the anonymous
tier of `/v1/sys/info`. `/v1/sys/cluster-status` additionally accepts a request
originating from a cluster machine — see [Cluster Status](#cluster-status).

**Everything else under `/v1/sys` requires a token and is ACL-checked**, at the
mount-relative path a policy author writes. The routes below do their work
inline rather than through the logical router, so their policy paths are worth
spelling out:

| Route | Policy path | Capability |
|-------|-------------|------------|
| `POST /v1/sys/backup` | `sys/backup` | `create`/`update` |
| `POST /v1/sys/restore` | `sys/restore` | `create`/`update` |
| `GET /v1/sys/export/{path}` | `sys/export/{path}` | `read` |
| `POST /v1/sys/import/{mount}` | `sys/import/{mount}` | `create`/`update` |
| `POST /v1/sys/exchange/export` | `sys/exchange/export` | `create`/`update` |
| `POST /v1/sys/exchange/import` | `sys/exchange/import` | `create`/`update` |
| `POST /v1/sys/cluster/remove-node` | `sys/cluster/remove-node` | `create`/`update` |
| `POST /v1/sys/cluster/leave` | `sys/cluster/leave` | `create`/`update` |
| `POST /v1/sys/cluster/failover` | `sys/cluster/failover` | `create`/`update` |
| `GET`/`POST` `/v1/sys/plugins…` | `sys/plugins…` | per method |
| `GET`/`PUT`/`DELETE` `/v2/sys/plugins/{name}/grants/credential-provider` | `sys/plugins/{name}/grants/credential-provider` | `read` / `update` / `delete` |
| `GET /v2/sys/plugins/{name}/entity-data` | `sys/plugins/{name}/entity-data` | `read` |
| `DELETE /v2/sys/plugins/{name}/entity-data/{entity_id}` | `sys/plugins/{name}/entity-data/{entity_id}` | `delete` |
| `GET`/`POST` `/v1/sys/scheduled-exports…` | `sys/scheduled-exports…` | per method |

`PUT /v1/sys/seal` is sudo-gated: `seal` is a `root_paths` entry, so it needs a
root token or a policy granting `sudo` on that path.

### Credential-provider grant (v2)

A plugin that declares `[capabilities.credential_provider]` (ABI 1.3) can supply
credentials to Connect only after an administrator approves it. The approval is
pinned to the SHA-256 of the manifest's `credential_provider` block, so any later
change to that block voids it until it is approved again. See
[features/self-accounts.md](../features/self-accounts.md) §4.

~~~
GET    /v2/sys/plugins/{name}/grants/credential-provider
PUT    /v2/sys/plugins/{name}/grants/credential-provider
DELETE /v2/sys/plugins/{name}/grants/credential-provider
~~~

`GET` returns the manifest's requested block, whether the plugin also requests
network access, the stored grant and whether it is `live` against the active
version. `PUT` takes no body: it approves exactly what the active manifest
declares, and answers `400` for a plugin that declares nothing. `DELETE` is
idempotent.

~~~
DELETE /v2/sys/plugins/{name}/entity-data/{entity_id}
~~~

Deletes one identity entity's data under one entity-scoped plugin, for
offboarding. The same data is removed automatically when an entity loses its
last alias. Each automatic purge is audited at
`sys/plugins/entity-data/{entity_id}` (`delete`, with `trigger` and `outcome`);
one that fails leaves a pending-purge marker, which the next automatic purge
and every call to this route retry.

~~~
GET /v2/sys/plugins/{name}/entity-data
~~~

How many records each entity holds under an entity-scoped plugin — **counts
only** (features/self-accounts.md Phase 5). The server lists keys, reads no
value and does not invoke the plugin, so no label, login name, target or
secret is returned. A record is an `accounts/<id>/meta` key; an entity holding
other data is listed with `0`. `display_name` is the entity's name from the
identity store, when known. `pending_purges` counts failed automatic purges
across every plugin. `404` for a plugin that is not registered or does not
declare `storage_scope = "entity"`. No user baseline policy grants it; the
built-in `administrator` policy reaches it through `path "*"`.

~~~json
{
  "entities": [ { "entity_id": "4f0c…", "display_name": "felipe", "accounts": 3 } ],
  "total_accounts": 3,
  "total_entities": 1,
  "pending_purges": 0
}
~~~

## Error Responses

Errors return an appropriate HTTP status code with a JSON body:

~~~json
{
  "errors": ["permission denied"]
}
~~~

| Status | Meaning |
|--------|---------|
| 400 | Invalid request |
| 403 | Permission denied |
| 404 | Not found |
| 500 | Internal server error |
| 503 | Vault is sealed |
