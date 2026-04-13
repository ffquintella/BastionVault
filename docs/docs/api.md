---
sidebar_position: 7
title: API Reference
---

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
