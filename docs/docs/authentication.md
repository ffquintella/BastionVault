---
sidebar_position: 9
title: Authentication
---

# Authentication Guide

BastionVault supports multiple authentication methods. Each method is mounted at a path and issues tokens that clients use for subsequent requests.

## Overview

| Method | Use Case | How It Works |
|--------|----------|-------------|
| **Token** | Direct token usage | Pass a known token directly |
| **Userpass** | Human operators | Username and password login |
| **AppRole** | Applications and services | Role ID + Secret ID exchange |
| **Certificate** | mTLS environments | TLS client certificate verification |

All methods produce a **token** on successful authentication. This token is then used for all subsequent API requests via the `X-Vault-Token` header or `token` cookie.

## Token Authentication

Token auth is always enabled and cannot be disabled. It is the most basic method: you provide a known token directly.

~~~bash
# Login with a token
bvault login s.my-token-value

# Or set the environment variable
export VAULT_TOKEN=s.my-token-value
bvault read secret/my-app
~~~

### Token Types

- **Service tokens** — standard tokens with a TTL, renewable
- **Batch tokens** — lightweight, non-renewable, not persisted to storage

### Using Tokens in API Calls

~~~bash
# Via header
curl -H "X-Vault-Token: s.my-token" https://127.0.0.1:8200/v1/secret/my-app

# Via cookie
curl -H "Cookie: token=s.my-token" https://127.0.0.1:8200/v1/secret/my-app
~~~

## Userpass Authentication

Username/password authentication for human operators.

### Setup

~~~bash
# Enable the method
bvault auth enable userpass

# Create a user
bvault write auth/userpass/users/alice \
  password=my-password \
  policies=dev-readonly,default
~~~

### Login

~~~bash
# CLI
bvault login --method=userpass username=alice password=my-password

# API
curl --request POST \
  --data '{"password": "my-password"}' \
  https://127.0.0.1:8200/v1/auth/userpass/login/alice
~~~

### User Management

~~~bash
# Update password
bvault write auth/userpass/users/alice password=new-password

# Update policies
bvault write auth/userpass/users/alice policies=admin,default

# List users
bvault list auth/userpass/users

# Delete a user
bvault delete auth/userpass/users/alice
~~~

## AppRole Authentication

AppRole is designed for machine-to-machine authentication. It uses a two-part credential: a **Role ID** (like a username) and a **Secret ID** (like a password).

### Setup

~~~bash
# Enable the method
bvault auth enable approle

# Create a role
bvault write auth/approle/role/my-service \
  secret_id_ttl=10m \
  token_ttl=20m \
  token_max_ttl=30m \
  policies=service-policy
~~~

### Obtain Credentials

The Role ID is static per role. The Secret ID is generated on demand.

~~~bash
# Get role ID (typically baked into application config)
bvault read auth/approle/role/my-service/role-id

# Generate secret ID (typically delivered by a deployment pipeline)
bvault write -f auth/approle/role/my-service/secret-id
~~~

### Login

~~~bash
# CLI
bvault write auth/approle/login \
  role_id=xxxx-xxxx \
  secret_id=yyyy-yyyy

# API
curl --request POST \
  --data '{"role_id": "xxxx-xxxx", "secret_id": "yyyy-yyyy"}' \
  https://127.0.0.1:8200/v1/auth/approle/login
~~~

### AppRole Options

| Option | Description |
|--------|-------------|
| `secret_id_ttl` | How long a generated secret ID is valid |
| `token_ttl` | Default TTL for issued tokens |
| `token_max_ttl` | Maximum TTL for issued tokens |
| `policies` | Comma-separated list of policies to attach |
| `secret_id_num_uses` | Max number of times a secret ID can be used |
| `bind_secret_id` | Require secret ID for login (default: true) |
| `token_bound_cidrs` | CIDR blocks that tokens can be used from |
| `secret_id_bound_cidrs` | CIDR blocks that secret IDs can be generated from |

### Recommended AppRole Workflow

1. An admin creates the role and retrieves the Role ID
2. The Role ID is embedded in the application configuration
3. A deployment pipeline generates a Secret ID and delivers it to the application
4. The application uses both to authenticate and obtain a token
5. The Secret ID is single-use or short-lived, so a compromised ID has limited impact

## Certificate Authentication

Certificate auth uses TLS client certificates to authenticate. The server verifies the client certificate against configured trusted CAs.

### Setup

The server must have TLS enabled with client certificate support:

~~~hcl
listener "tcp" {
  address                            = "0.0.0.0:8200"
  tls_cert_file                      = "/etc/bvault/tls/server.crt"
  tls_key_file                       = "/etc/bvault/tls/server.key"
  tls_client_ca_file                 = "/etc/bvault/tls/client-ca.pem"
  tls_require_and_verify_client_cert = true
}
~~~

Enable the auth method:

~~~bash
bvault auth enable cert
~~~

### Login

~~~bash
bvault login --method=cert \
  --client-cert=/path/to/client.crt \
  --client-key=/path/to/client.key
~~~

## Choosing an Auth Method

| Scenario | Recommended Method |
|----------|-------------------|
| Quick testing, development | Token (root token or static) |
| Human operators | Userpass |
| Applications, CI/CD pipelines | AppRole |
| Service mesh, mutual TLS environments | Certificate |
| Multiple methods needed | Enable several; assign different policies to each |

## Token Lifecycle

All auth methods produce tokens. Key lifecycle concepts:

- **TTL** — tokens expire after their time-to-live
- **Renewable** — service tokens can be renewed before they expire to extend their TTL
- **Max TTL** — the absolute maximum lifetime, even with renewals
- **Revocation** — tokens can be explicitly revoked; disabling an auth method revokes all its tokens

## Policies and Auth

Every token has a list of attached policies. When authenticating:

1. The auth method determines which policies to attach (based on role, user, or certificate configuration)
2. The `default` policy is always included
3. The token inherits the combined capabilities of all its policies
4. The `root` policy grants unrestricted access

See the [Administration Guide](./administration.md) for policy syntax and management.
