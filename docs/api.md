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
  "cases": [
    { "path": "secret/data/x", "capability": "read" },
    { "path": "secret/data/x", "capability": "delete" }
  ]
}
~~~

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
      "denied_by_deny": false
    }
  ]
}
~~~

`match_kind` is one of `exact` | `prefix` | `segment_wildcard` | `none`.
`matched_path` / `match_kind` are advisory; `allowed` / `denied_by_deny`
are authoritative (produced by the real matcher).

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
    { "path": "secret/data/x", "capability": "delete", "expect": "deny" }
  ]
}
~~~

### Server Info

Returns identity + lifecycle facts the GUI's *Server Info* dialog
also reads. Useful for monitoring tooling that wants a single
endpoint covering version, uptime, and storage flavour.

~~~
GET /v1/sys/info
~~~

Response:

~~~json
{
  "version": "0.5.20",
  "started_at": "2026-05-14T18:00:00Z",
  "uptime_seconds": 3712,
  "initialized": true,
  "sealed": false,
  "storage_type": "hiqlite"
}
~~~

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
  "password": "my-password"
}
~~~

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
  "policies": "default,admin"
}
~~~

**Read a user**

~~~
GET /v1/auth/{mount}/users/{username}
~~~

**Delete a user**

~~~
DELETE /v1/auth/{mount}/users/{username}
~~~

**List users**

~~~
LIST /v1/auth/{mount}/users
~~~

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

System endpoints like `/v1/sys/init`, `/v1/sys/seal-status`, and `/v1/sys/unseal` do not require authentication.

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
