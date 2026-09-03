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
  "node_id": "node-a",
  "cluster_uuid": "…",
  "epoch": 0,
  "enrolled_nodes": 3,
  "this_node_enrolled": true,
  "recovery": "none",
  "pqc_key_cache_ttl_secs": 60,
  "sealed": false,
  "initialized": true
}
~~~

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

Only the `secret` credential kind (ssh-password shape) is resolved
server-side today. v1 `POST /v1/rustion/session/open` (raw
`credential_material`) is unchanged.

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
| `GET`/`POST` `/v1/sys/scheduled-exports…` | `sys/scheduled-exports…` | per method |

`PUT /v1/sys/seal` is sudo-gated: `seal` is a `root_paths` entry, so it needs a
root token or a policy granting `sudo` on that path.

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
