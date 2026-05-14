# Administration Guide

This guide covers day-to-day administration of a BastionVault deployment: initialization, seal/unseal operations, secret engine management, policy management, and monitoring.

## Server Lifecycle

### Starting the Server

~~~bash
bvault server --config /etc/bvault/config.hcl
~~~

Or as a daemon:

~~~hcl
# In config.hcl
daemon       = true
daemon_user  = "bvault"
daemon_group = "bvault"
pid_file     = "/var/run/bvault.pid"
~~~

Use `make run-dev` for local development with the included `config/dev.hcl`.

### Initialization

A new vault must be initialized before first use. Initialization generates the root encryption key and splits it into shares using Shamir's Secret Sharing.

~~~bash
# Single key (development only)
bvault operator init --key-shares=1 --key-threshold=1

# Production: 5 shares, 3 required to unseal
bvault operator init --key-shares=5 --key-threshold=3
~~~

Store each key share separately. Distribute them to different trusted operators.

### Sealing and Unsealing

When BastionVault starts (or is explicitly sealed), it enters a **sealed** state. All data is encrypted and inaccessible. Operators must provide enough key shares to meet the threshold.

**Unseal:**

~~~bash
# Provide key shares one at a time
bvault operator unseal    # prompts for key
bvault operator unseal <key-share>
~~~

Repeat until the threshold is met. Check progress with:

~~~bash
bvault status
~~~

**Seal:**

~~~bash
bvault operator seal
~~~

Sealing the vault immediately encrypts all data and revokes all tokens. Use this in emergency situations or during maintenance.

## Secrets Engines

Secrets engines are mounted at paths and handle read/write operations for that path prefix.

### Enable a Secrets Engine

~~~bash
bvault secrets enable kv
bvault secrets enable --path=app-secrets --description="Application secrets" kv
~~~

### List Secrets Engines

~~~bash
bvault secrets list
~~~

### Disable a Secrets Engine

All data managed by the engine is permanently deleted.

~~~bash
bvault secrets disable app-secrets/
~~~

### Move a Secrets Engine

~~~bash
bvault secrets move secret/ generic/
~~~

### Working with KV Secrets

Write a secret:

~~~bash
bvault write secret/database host=db.example.com port=5432 password=s3cret
~~~

Read a secret:

~~~bash
bvault read secret/database
bvault read --field=password secret/database
~~~

List secrets:

~~~bash
bvault list secret/
~~~

Delete a secret:

~~~bash
bvault delete secret/database
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

### Scope and group qualifiers

Path rules may additionally carry `scopes = [...]` and/or `groups = [...]`
qualifiers that gate the rule's capabilities on attributes of the
*target*, not the path string:

~~~hcl
# Owner: only entries this token's entity_id owns.
# `scopes = ["owner", "shared"]` is additive — owner OR explicit share.
path "secret/data/users/*" {
  capabilities = ["read", "list", "update"]
  scopes       = ["owner", "shared"]
}

# Group: only resources that are members of an asset group named
# `project-phoenix` or `shared-platform`.
path "resource/data/*" {
  capabilities = ["read", "list"]
  groups       = ["project-phoenix", "shared-platform"]
}
~~~

Supported `scopes`: `owner` (caller's `entity_id` matches the
target's owner record), `shared` (an explicit `SecretShare` exists),
`any` (default; equivalent to omitting `scopes`). Empty `scopes`
means legacy unscoped semantics.

`groups` and `scopes` are additive per rule: when both are present
the rule applies if the group filter *or* the scope filter passes.

### Policy metadata (opt-in feature flags)

A top-level `metadata { key = "value" }` block on a policy carries
declarative opt-ins that the rest of the system reads back as a flat
string map. Today one flag is consumed:

~~~hcl
# Opt the policy-holder into seeing group shares in their
# "Shared with me" feed.
name = "group-shared-resources"

metadata {
  group_shared_resources = "true"
}
~~~

Attach this policy (or merge the `metadata` block into an existing
policy) to anyone who should see resources/secrets that have been
shared with an identity group they belong to. The flag is a
*visibility* gate — the actual ACL is still granted by the user's
existing policies. Without the flag, group shares are invisible to
the user even when they are a member of the target group.

### Managing Policies

~~~bash
# Write a policy from file
bvault policy write app-readonly policy.hcl

# List policies
bvault policy list

# Read a policy
bvault policy read app-readonly

# Delete a policy
bvault policy delete app-readonly
~~~

The `default` and `root` policies are built-in and cannot be deleted.

## Identity Groups

Identity groups attach a set of policies to a *named collection of
principals* — UserPass usernames (`user` groups) or AppRole role names
(`app` groups). At login time, the policies attached to every group
the caller is a member of are unioned with their direct policies.

~~~bash
# Create a user group with two members and one policy.
bvault write identity/group/user/engineering \
  description="Platform engineering team" \
  members="alice,bob,felipe2" \
  policies="engineering-shared"

# Read it back.
bvault read identity/group/user/engineering

# List all user groups.
bvault list identity/group/user

# AppRole groups live under group/app.
bvault write identity/group/app/ci-bots \
  members="github-runner,builder" \
  policies="ci-readonly"
~~~

Groups also double as **share targets** — see *Sharing* below.

## Sharing

Sharing grants a named subset of capabilities (`read`, `list`,
`update`, `delete`, `create`) on a specific target (a KV secret, a
resource, an asset group, or a file) to a single grantee. Two
grantee kinds are supported:

- **`entity`** *(default)* — the grantee is a stable `entity_id` UUID
  (resolved from a userpass login or appRole role at first
  authentication). The recipient sees the target on their *Shared
  with me* feed and the rule with `scopes = ["shared"]` resolves to
  the granted capabilities.
- **`group_user` / `group_app`** — the grantee is an identity group.
  Group shares are *visibility-only*: they surface the target on
  each member's *Shared with me* feed **only when** the member has a
  policy whose `metadata.group_shared_resources` is `"true"`. The
  actual ACL is still owned by the member's regular policies, so
  membership churn cannot escalate access on its own.

### Granting a share

~~~bash
# Direct entity share — grant read on a resource to alice.
bvault write identity/sharing/by-target/resource/$(printf 'server-01' | base64 -w0) \
  /<alice-entity-uuid> \
  target_kind=resource \
  target_path=server-01 \
  grantee_kind=entity \
  capabilities=read,list

# Group share — grant read on a KV secret to the engineering group.
bvault write identity/sharing/by-target/kv-secret/$(printf 'secret/app/db' | base64 -w0)/engineering \
  target_kind=kv-secret \
  target_path=secret/app/db \
  grantee_kind=group_user \
  capabilities=read,list
~~~

### Listing the caller's shares

~~~bash
# Returns direct entity shares plus, when group_shared_resources is
# set on at least one of the caller's policies, group shares the
# caller is entitled to.
bvault list identity/sharing/for-me
~~~

### Revoking a share

~~~bash
bvault delete identity/sharing/by-target/<kind>/<b64>/<grantee> \
  grantee_kind=group_user
~~~

The optional `grantee_kind` body field tells the server which
by-grantee pointer prefix to clear; omitting it defaults to
`entity` for compatibility with shares written before group
grantees existed.

## Auth Method Management

### Enable an Auth Method

~~~bash
bvault auth enable userpass
bvault auth enable --path=prod-approle approle
~~~

### List Auth Methods

~~~bash
bvault auth list
~~~

### Disable an Auth Method

All tokens issued by this auth method are revoked.

~~~bash
bvault auth disable userpass/
~~~

### Configure Userpass

Create a user:

~~~bash
bvault write auth/userpass/users/admin password=s3cret policies=admin,default
~~~

Update password:

~~~bash
bvault write auth/userpass/users/admin password=new-password
~~~

Delete a user:

~~~bash
bvault delete auth/userpass/users/admin
~~~

### Configure AppRole

Create a role:

~~~bash
bvault write auth/approle/role/my-app \
  secret_id_ttl=10m \
  token_ttl=20m \
  token_max_ttl=30m \
  policies=app-readonly
~~~

Get the role ID:

~~~bash
bvault read auth/approle/role/my-app/role-id
~~~

Generate a secret ID:

~~~bash
bvault write -f auth/approle/role/my-app/secret-id
~~~

Login with AppRole:

~~~bash
bvault write auth/approle/login role_id=<role-id> secret_id=<secret-id>
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
