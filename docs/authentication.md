# Authentication Guide

BastionVault supports multiple authentication methods. Each method is mounted at a path and issues tokens that clients use for subsequent requests.

## Overview

| Method | Use Case | How It Works |
|--------|----------|-------------|
| **Token** | Direct token usage | Pass a known token directly |
| **Userpass** | Human operators | Username and password login |
| **AppID** | Applications and services | Role ID + Secret ID exchange |
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

### Reserved Token Metadata

`auth/token/create` accepts a `meta` map of free-form annotations that ride on
the child token and appear in the audit log. A set of keys is **reserved**: the
ones an auth backend stamps to record *how* the principal authenticated, and
which the server then reads back as authorization input. A create request that
supplies any of them is refused with ``meta key(s) `<k>` are reserved`` (naming
every offending key), and the attempt is logged to the `security` target.

| Reserved key | Why |
|---|---|
| `spiffe_id`, `machine_id` | `spiffe_id` **is** what machine-bound means to the server-wide FerroGate `require_machine_identity` gate, and (with `mount_path`) is what makes a token usable as the `machine_token` of an AppID machine-bound login |
| `username`, `entity_id`, `mount_path`, `role_name`, `role` | Substituted into templated policy paths; used to resolve the principal's namespace assignment and identity entity |
| `approle_env_*` | The AppID environment scope the KV v2 engine enforces |
| `namespace_path`, `namespace_id`, `child_visible` | The token's namespace binding — set from the request's `X-BastionVault-Namespace` header, never from `meta` |
| `auth_method`, `groups`, `subject`, `name_id`, `name_id_format`, `ferrogate_kid`, `session_id` | Login provenance; audit attribution |
| `approle_machine_bypass`, `machine_identity_exempt` | Not read from metadata at all — the AppID machine-binding exemption is a typed field on the token precisely so it cannot be forged. Refused so the metadata spelling cannot be mistaken for it |

Any other key is yours. Reserving them is a security boundary, not a
namespacing convention: a caller that could write `spiffe_id` could mint itself
a token that passes the machine-identity gate with no attestation, and one that
could write `username` or `entity_id` could redirect a templated policy at
another principal's paths. Note that the built-in `default` policy does not
grant `auth/token/create`, so only an explicitly privileged token can reach
this path at all.

The same list is enforced at a second write point: an **OIDC or SAML role may
not map a claim or attribute onto a reserved key**. The value there comes from
the identity provider, so a role configured with `claim_mappings = {"dept" =
"spiffe_id"}` would hand the IdP the machine-identity gate. The role write is
refused, validated against the role as it will be stored — so an existing role
carrying such a mapping has to be corrected on its next write rather than kept.
SAML permits one exception, `username`, because its attribute mapping is how
the principal gets named; OIDC allows none, since `user_claim` already does
that job there.

A role written *before* this check existed still loads, so login enforces the
same list a second time: a mapping onto a reserved key is dropped — only that
mapping, the rest of the role still applies and the login still succeeds — and
a `security`-target warning names the role and the key so it can be found and
corrected. Grep the server log for `dropping the mapping`.

#### What a child token keeps, and what it cannot shed

Refusing a forged key stops a child token *gaining* one. The reverse matters
too, because the child's `meta` comes from the request body — so a key the
parent carries would otherwise be simply absent on the child. For a key that
names an identity that is harmless. For one that carries a **restriction** it
would be an escape, so those are inherited:

- **`approle_env_*`** — the AppID environment scope. Without inheritance a
  scoped AppID with a grant on `auth/token/create` minted itself a child that
  read every environment, including the base (non-env) secrets a scoped token
  is barred from.
- **The namespace binding** — clamped to the parent's. An absent
  `X-BastionVault-Namespace` header inherits the parent's namespace instead of
  defaulting to root, a namespace the parent may not operate in is refused, and
  `child_visible` is refused (not silently dropped) when the parent lacks it.
- **`token_bound_cidrs`** and the AppID **machine-binding exemption** — both
  typed fields on the token rather than metadata, inherited for the same
  reason.

The identities are deliberately *not* inherited: a child of a machine-bound
token does **not** carry `spiffe_id`, so it does not satisfy
`require_machine_identity` by descent, and it does not inherit `username`,
`entity_id`, `role_name` or `mount_path` — which would attribute its actions to
the parent's principal and hand it the parent's namespace grants. The rule is
"does the key's presence take access away?" — inherited if so, never
otherwise.

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

## AppID Authentication

AppID (mounted as the Vault-compatible `approle` auth type) is designed for machine-to-machine authentication. It uses a two-part credential: a **Role ID** (like a username) and a **Secret ID** (like a password).

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

#### Machine identity (FerroGate)

When the server's machine-identity gate is enabled (the default), every AppID
login must also present a **FerroGate machine token** whose machine is bound to
the role under the **Machines** tab. Obtain the machine token from the local MIA
(see [FerroGate machine auth](ferrogate-machine-auth.md)) and pass it as
`machine_token`:

~~~bash
curl --request POST \
  --data '{"role_id": "xxxx-xxxx", "secret_id": "yyyy-yyyy", "machine_token": "zzzz"}' \
  https://127.0.0.1:8200/v1/auth/approle/login
~~~

The login validates `role_id` and `secret_id` first (a wrong value returns
`400`), then checks the source IP filter, the machine binding and the namespace
assignment. A role with a correct `role_id`/`secret_id` that still returns `403
Permission denied` is failing one of these later checks — most often the
namespace (below).

##### Per-application bypass

An application that cannot run a machine identity agent can be exempted from
machine binding on its own ID, without weakening the gate for anything else:

~~~bash
bvault write auth/approle/role/my-service bypass_machine_binding=true
~~~

That ID then logs in with `role_id` + `secret_id` alone; its bound machines are
not consulted and no `machine_token` is accepted as proof of anything. Setting
it back to `false` (or deleting
`auth/approle/role/my-service/bypass-machine-binding`) re-gates the ID. Every
write of the flag is recorded in the AppID audit trail and logged to the
`security` target, and each bypassed login is logged too. Pair it with a source
IP filter so the credential is only usable from where the application runs.

The bypass covers the token as well as the login. The server-wide FerroGate
`require_machine_identity` flag is a separate gate at the token layer — with it
on, every authenticated request must ride a machine-bound token — and a token
minted by a bypassed AppID login is exempt from it. Without that the escape
hatch was decorative on any server with the flag on: the login succeeded and
then every request the token made was refused, audited as
`reason=machine-identity`.

The exemption is a property of the token, stamped at issuance from the role's
flag. It is not carried in token metadata, so it cannot be forged by a caller
that supplies `meta` to `auth/token/create` (which also refuses the metadata
spelling outright — see [Reserved Token Metadata](#reserved-token-metadata)); a
child token inherits it from its parent and can never acquire one its parent
lacks. Clearing the role flag
re-gates the ID at the next login — tokens already issued keep the exemption
until they expire, so revoke them if that matters.

#### Source IP filter

`bound_source_ips` restricts where an ID may authenticate from. Unlike
`secret_id_bound_cidrs` (CIDR blocks only), a list may mix four forms:

| Form | Example |
|---|---|
| Single address | `10.0.0.5`, `2001:db8::1` |
| CIDR block | `192.168.1.0/24`, `2001:db8::/64` |
| Address + dotted netmask (IPv4) | `172.16.0.0/255.255.0.0` |
| Inclusive range | `10.9.0.10-10.9.0.20` |

~~~bash
bvault write auth/approle/role/my-service \
  bound_source_ips="10.0.0.5,192.168.1.0/24,172.16.0.0/255.255.0.0,10.9.0.10-10.9.0.20"

# Or on its own sub-path, which also supports read and delete
bvault write auth/approle/role/my-service/bound-source-ips bound_source_ips="10.0.0.5"
bvault delete auth/approle/role/my-service/bound-source-ips
~~~

A login from any address outside the list is refused, and so is one the server
cannot attribute a source address to. A malformed entry is rejected when the
role is written, not silently ignored at login time.

The address matched is the **client** IP, not the socket peer. When
`BASTIONVAULT_TRUSTED_PROXIES` is set and the request arrives through one of
those proxies, the rule is evaluated against the address resolved from the
`X-Forwarded-For` / `Forwarded` chain; with no trusted proxies configured
(the default) it is the socket peer's IP, with its source port stripped.
`secret_id_bound_cidrs` and a secret ID's own `cidr_list` are matched the
same way.

#### Token source-address binding

`bound_source_ips`, `secret_id_bound_cidrs` and a secret ID's `cidr_list`
constrain the **login**. `token_bound_cidrs` constrains the **issued token**:
it is stamped onto the token at login and checked on every subsequent request
the token is presented on. The two are independent — a login from anywhere may
mint a token that is only usable from inside the block, and a token bound to a
block it is never presented from is simply unusable.

~~~bash
bvault write auth/approle/role/my-service token_bound_cidrs="10.0.0.0/24"

# Or on its own sub-path, which also supports read and delete
bvault write auth/approle/role/my-service/token-bound-cidrs \
  token_bound_cidrs="10.0.0.0/24"
bvault delete auth/approle/role/my-service/token-bound-cidrs
~~~

An entry may be a single address (`10.0.0.5`), a CIDR block
(`10.0.0.0/24`, `2001:db8::/64`), or an address with a port
(`10.0.0.5:8200` — the port is recorded but ignored when matching, so the
client's ephemeral source port can never make the rule unmatchable). The same
client IP resolution as above applies: behind a configured trusted proxy the
derived client address is what is matched.

A request carrying a bound token is refused with `403 Permission denied` when
it arrives from outside the block, and also when the server cannot determine a
source address for it — an address that is unknown cannot be shown to satisfy
the rule. The refusal is logged to the `security` target and does **not**
consume one of a use-limited token's remaining uses.

Two properties are worth knowing before you rely on it:

- **A secret ID may narrow it.** `token_bound_cidrs` on a secret ID
  (`auth/approle/role/<name>/secret-id`) replaces the role's list for tokens
  minted with that secret ID. It is validated to be a subset of the role's
  list when the secret ID is issued, so it can only narrow, never widen.
- **A child token inherits it.** A bound token cannot mint an unbound child
  via `auth/token/create`; the binding is copied onto the child, so the
  restriction cannot be escaped by chaining a token.

The same field is available on UserPass users
(`auth/<mount>/users/<name>`), where the pre-`token_*` alias `bound_cidrs`
is also accepted and kept in sync with it.

> **Enforcement is new — see `CHANGELOG.md`.** Every release up to and
> including 0.42.1 parsed, stored and echoed back
> `token_bound_cidrs` without ever evaluating it. If you set it on a role
> before upgrading, it did nothing — audit your roles and confirm the blocks
> name the addresses your clients actually reach the vault from. Tokens issued
> before the upgrade are unaffected and stay unrestricted; only tokens minted
> afterwards carry a binding.

#### Namespace-scoped roles

A role restricted to a namespace (via its namespace assignment) may **only** be
used from that namespace. Both the login and every subsequent request must carry
the `X-BastionVault-Namespace` header naming the namespace; request paths stay
mount-relative. A login sent without it targets the root namespace and is
rejected with `403 Permission denied`, even when every credential is valid — the
named policy and the secret both live inside the namespace and are invisible at
root.

~~~bash
# Login into namespace "dti/esi"
curl --request POST \
  -H "X-BastionVault-Namespace: dti/esi" \
  --data '{"role_id": "xxxx-xxxx", "secret_id": "yyyy-yyyy", "machine_token": "zzzz"}' \
  https://127.0.0.1:8200/v1/auth/approle/login

# Read a secret using the issued token, still scoped to the namespace
curl -H "X-BastionVault-Namespace: dti/esi" \
     -H "X-Vault-Token: <issued-token>" \
     https://127.0.0.1:8200/v1/secret/data/github/rustion
~~~

> A namespace can also be selected by prefixing the request path
> (`dti/esi/secret/data/github/rustion`) instead of sending the header — but do
> not combine the two forms in one request; a path prefix together with the
> header is refused.

### AppID Options

| Option | Description |
|--------|-------------|
| `secret_id_ttl` | How long a generated secret ID is valid |
| `token_ttl` | Default TTL for issued tokens |
| `token_max_ttl` | Maximum TTL for issued tokens |
| `policies` | Comma-separated list of policies to attach |
| `secret_id_num_uses` | Max number of times a secret ID can be used |
| `bind_secret_id` | Require secret ID for login (default: true) |
| `token_bound_cidrs` | CIDR blocks the issued token may be used from, enforced on every request it is presented on (empty = any) |
| `secret_id_bound_cidrs` | CIDR blocks that secret IDs can be generated from |
| `bound_source_ips` | Source addresses a login may come from: single IPs, CIDR blocks, address + dotted netmask, or `start-end` ranges, mixed freely (empty = any) |
| `bypass_machine_binding` | Log in with App ID credentials alone — no FerroGate machine token, bound machines ignored (default: false) |

### Recommended AppID Workflow

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
| Applications, CI/CD pipelines | AppID |
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
3. **Identity-group policies are unioned in**: every user group containing the caller's username (UserPass / FIDO2) and every app group containing the caller's role name (AppID) contributes its `policies` list. Group membership changes take effect on the *next* login.
4. The token inherits the combined capabilities of all its policies
5. The `root` policy grants unrestricted access

When a token has no `entity_id` in its metadata (typically because
it was issued before lazy provisioning landed), the
`identity/entity/self` endpoint will resolve the entity by alias
(`mount_path` + `username`/`role_name`) and lazily create it via
`get_or_create_entity` — owner-scoped and sharing-aware UI keeps
working without forcing a re-login.

See the [Administration Guide](./administration.md) for policy
syntax, scope/group qualifiers, identity groups, and sharing.
