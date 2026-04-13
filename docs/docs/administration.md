---
sidebar_position: 8
title: Administration
---

# Administration Guide

This guide covers day-to-day administration of a BastionVault deployment: initialization, seal/unseal operations, secret engine management, policy management, and monitoring.

## Server Lifecycle

### Starting the Server

~~~bash
rvault server --config /etc/rvault/config.hcl
~~~

Or as a daemon:

~~~hcl
# In config.hcl
daemon       = true
daemon_user  = "rvault"
daemon_group = "rvault"
pid_file     = "/var/run/rvault.pid"
~~~

Use `make run-dev` for local development with the included `config/dev.hcl`.

### Initialization

A new vault must be initialized before first use. Initialization generates the root encryption key and splits it into shares using Shamir's Secret Sharing.

~~~bash
# Single key (development only)
rvault operator init --key-shares=1 --key-threshold=1

# Production: 5 shares, 3 required to unseal
rvault operator init --key-shares=5 --key-threshold=3
~~~

Store each key share separately. Distribute them to different trusted operators.

### Sealing and Unsealing

When BastionVault starts (or is explicitly sealed), it enters a **sealed** state. All data is encrypted and inaccessible. Operators must provide enough key shares to meet the threshold.

**Unseal:**

~~~bash
# Provide key shares one at a time
rvault operator unseal    # prompts for key
rvault operator unseal <key-share>
~~~

Repeat until the threshold is met. Check progress with:

~~~bash
rvault status
~~~

**Seal:**

~~~bash
rvault operator seal
~~~

Sealing the vault immediately encrypts all data and revokes all tokens. Use this in emergency situations or during maintenance.

## Secrets Engines

Secrets engines are mounted at paths and handle read/write operations for that path prefix.

### Enable a Secrets Engine

~~~bash
rvault secrets enable kv
rvault secrets enable --path=app-secrets --description="Application secrets" kv
~~~

### List Secrets Engines

~~~bash
rvault secrets list
~~~

### Disable a Secrets Engine

All data managed by the engine is permanently deleted.

~~~bash
rvault secrets disable app-secrets/
~~~

### Move a Secrets Engine

~~~bash
rvault secrets move secret/ generic/
~~~

### Working with KV Secrets

Write a secret:

~~~bash
rvault write secret/database host=db.example.com port=5432 password=s3cret
~~~

Read a secret:

~~~bash
rvault read secret/database
rvault read --field=password secret/database
~~~

List secrets:

~~~bash
rvault list secret/
~~~

Delete a secret:

~~~bash
rvault delete secret/database
~~~

## Policy Management

Policies control what paths a token can access and what operations it can perform.

### Policy Syntax

Policies are written in HCL:

~~~hcl
# Allow read-only access to application secrets
path "secret/app/*" {
  capabilities = ["read", "list"]
}

# Allow full access to the team's secrets
path "secret/team-a/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Deny access to infrastructure secrets
path "secret/infra/*" {
  capabilities = ["deny"]
}
~~~

Available capabilities: `create`, `read`, `update`, `delete`, `list`, `sudo`, `deny`.

### Managing Policies

~~~bash
# Write a policy from file
rvault policy write app-readonly policy.hcl

# List policies
rvault policy list

# Read a policy
rvault policy read app-readonly

# Delete a policy
rvault policy delete app-readonly
~~~

The `default` and `root` policies are built-in and cannot be deleted.

## Auth Method Management

### Enable an Auth Method

~~~bash
rvault auth enable userpass
rvault auth enable --path=prod-approle approle
~~~

### List Auth Methods

~~~bash
rvault auth list
~~~

### Disable an Auth Method

All tokens issued by this auth method are revoked.

~~~bash
rvault auth disable userpass/
~~~

### Configure Userpass

Create a user:

~~~bash
rvault write auth/userpass/users/admin password=s3cret policies=admin,default
~~~

Update password:

~~~bash
rvault write auth/userpass/users/admin password=new-password
~~~

Delete a user:

~~~bash
rvault delete auth/userpass/users/admin
~~~

### Configure AppRole

Create a role:

~~~bash
rvault write auth/approle/role/my-app \
  secret_id_ttl=10m \
  token_ttl=20m \
  token_max_ttl=30m \
  policies=app-readonly
~~~

Get the role ID:

~~~bash
rvault read auth/approle/role/my-app/role-id
~~~

Generate a secret ID:

~~~bash
rvault write -f auth/approle/role/my-app/secret-id
~~~

Login with AppRole:

~~~bash
rvault write auth/approle/login role_id=<role-id> secret_id=<secret-id>
~~~

## Monitoring

BastionVault exposes Prometheus metrics. The collection interval is configurable:

~~~hcl
collection_interval = 15  # seconds
~~~

Metrics include system-level data (CPU, memory, disk) and HTTP request metrics.

## Storage Encryption

BastionVault encrypts all data at rest using a barrier encryption layer. The default is `ChaCha20-Poly1305` with `ML-KEM-768` post-quantum key wrapping.

The barrier type is set in the configuration:

~~~hcl
barrier_type = "chacha20-poly1305"   # default, recommended
# barrier_type = "aes-gcm"          # legacy, for backward compatibility
~~~

The encryption key is derived from the unseal keys during the unseal process. When the vault is sealed, the encryption key is discarded from memory.

## Production Checklist

- [ ] Use TLS (`tls_disable = false`) with proper certificates
- [ ] Use multiple unseal key shares (`key-shares >= 3`, `key-threshold >= 2`)
- [ ] Distribute unseal keys to separate trusted operators
- [ ] Use `chacha20-poly1305` barrier type (the default)
- [ ] Run as a dedicated system user via daemon mode
- [ ] Configure appropriate log level (`info` or `warn` for production)
- [ ] Set up monitoring for the metrics endpoint
- [ ] Create scoped policies; avoid using the root token for regular operations
- [ ] Use AppRole or userpass for application authentication instead of static tokens
- [ ] Back up the storage directory regularly
- [ ] Test unseal procedures before they are needed in an emergency
