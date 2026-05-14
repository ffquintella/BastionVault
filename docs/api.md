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

User-group and AppRole-group records that fan policies out to every
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

### AppRole Login

~~~
POST /v1/auth/{mount}/login
~~~

~~~json
{
  "role_id": "xxxx-xxxx",
  "secret_id": "yyyy-yyyy"
}
~~~

### AppRole Management

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
