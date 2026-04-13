---
sidebar_position: 6
title: CLI Reference
---

# CLI Reference

BastionVault provides the `rvault` command-line tool for interacting with a running server. The CLI is compatible with HashiCorp Vault's command structure.

## Global Options

These options apply to all commands that connect to a server:

| Option | Env Variable | Description |
|--------|-------------|-------------|
| `--address` | `VAULT_ADDR` | Server address (default: `https://127.0.0.1:8200`) |
| `--token` | `VAULT_TOKEN` | Authentication token |
| `--ca-cert` | `VAULT_CACERT` | Path to CA certificate for server verification |
| `--client-cert` | `VAULT_CLIENT_CERT` | Path to client certificate for mTLS |
| `--client-key` | `VAULT_CLIENT_KEY` | Path to client private key |
| `--tls-skip-verify` | `VAULT_SKIP_VERIFY` | Skip TLS verification (not recommended) |
| `--tls-server-name` | `VAULT_TLS_SERVER_NAME` | TLS SNI hostname |
| `--header` | | Custom HTTP header as `key=value` (repeatable) |
| `--format` | `VAULT_FORMAT` | Output format: `table`, `json`, `yaml`, `raw` |
| `--log-level` | `VAULT_LOG_LEVEL` | Log level: `trace`, `debug`, `info`, `warn`, `error` |

## server

Start a BastionVault server.

~~~bash
rvault server --config /path/to/config.hcl
~~~

| Option | Description |
|--------|-------------|
| `--config` | Path to configuration file or directory (required) |
| `--log-file` | Path to log file |
| `--log-level` | Log verbosity (default: `warn`) |

## status

Print the seal status of the vault.

~~~bash
rvault status
rvault status --format=json
~~~

Returns the sealed state, number of key shares, threshold, and unseal progress.

## operator init

Initialize a new vault. Generates the root key and splits it using Shamir's Secret Sharing.

~~~bash
rvault operator init
rvault operator init --key-shares=5 --key-threshold=3
~~~

| Option | Description |
|--------|-------------|
| `--key-shares` | Number of key shares to generate |
| `--key-threshold` | Number of shares required to unseal |

Returns a list of unseal keys and a root token. Store these securely.

## operator unseal

Provide an unseal key share. Must be called enough times to meet the threshold.

~~~bash
rvault operator unseal
rvault operator unseal 7df5ff90cd9417e04cbb9f6db65e0b16ce265d5108fd07e45bdae1a35bf5da6a
~~~

If the key is not provided as an argument, you will be prompted for it.

## operator seal

Seal the vault. All secrets become inaccessible until it is unsealed again.

~~~bash
rvault operator seal
~~~

## read

Read data from a path.

~~~bash
rvault read secret/my-secret
rvault read --field=password secret/my-secret
rvault read --format=json secret/my-secret
~~~

| Option | Description |
|--------|-------------|
| `--field` | Print only the specified field value |

## write

Write data to a path.

~~~bash
rvault write secret/my-secret foo=bar
rvault write secret/my-secret password=@/path/to/file
rvault write secret/my-secret data=-
~~~

Values can be specified as:
- `key=value` — literal value
- `key=@/path/to/file` — read value from a file
- `key=-` — read value from stdin

## delete

Delete data at a path.

~~~bash
rvault delete secret/my-secret
~~~

## list

List keys at a path.

~~~bash
rvault list secret/
rvault list --format=json auth/
~~~

## login

Authenticate to BastionVault and obtain a token.

~~~bash
# Token auth (default)
rvault login s.my-token-value

# Username/password
rvault login --method=userpass username=admin password=secret

# Certificate
rvault login --method=cert --client-cert=client.crt --client-key=client.key
~~~

| Option | Description |
|--------|-------------|
| `--method` | Auth method: `token` (default), `userpass`, `cert` |
| `--path` | Mount path of the auth method (defaults to method name) |
| `--no-print` | Do not display the token after login |

## auth enable

Enable an authentication method.

~~~bash
rvault auth enable userpass
rvault auth enable --path=my-approle --description="App authentication" approle
~~~

| Option | Description |
|--------|-------------|
| `--path` | Mount path (defaults to the method type) |
| `--description` | Human-readable description |

## auth disable

Disable an authentication method. All tokens from this method are revoked.

~~~bash
rvault auth disable userpass/
~~~

## auth list

List all enabled authentication methods.

~~~bash
rvault auth list
rvault auth list --format=json
~~~

## auth move

Move an authentication method to a different path.

~~~bash
rvault auth move approle/ new-approle/
~~~

## policy write

Create or update a policy from a file.

~~~bash
rvault policy write my-policy policy.hcl
rvault policy write my-policy -    # read from stdin
~~~

## policy read

Read a policy by name.

~~~bash
rvault policy read my-policy
~~~

## policy delete

Delete a policy by name. The `default` and `root` policies cannot be deleted.

~~~bash
rvault policy delete my-policy
~~~

## policy list

List all policies.

~~~bash
rvault policy list
~~~

## secrets enable

Enable a secrets engine.

~~~bash
rvault secrets enable kv
rvault secrets enable --path=kv-v2 --version=2 kv
rvault secrets enable --max-lease-ttl=30m --path=short-lived kv
~~~

| Option | Description |
|--------|-------------|
| `--path` | Mount path (defaults to the engine type) |
| `--description` | Human-readable description |
| `--default-lease-ttl` | Default lease duration |
| `--max-lease-ttl` | Maximum lease duration |
| `--version` | Engine version |

## secrets disable

Disable a secrets engine. All secrets and configuration for this engine are removed.

~~~bash
rvault secrets disable kv/
~~~

## secrets list

List all enabled secrets engines.

~~~bash
rvault secrets list
rvault secrets list --format=json
~~~

## secrets move

Move a secrets engine to a different path.

~~~bash
rvault secrets move secret/ generic/
~~~

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error |
| 2 | Insufficient data or parameters |
