# CLI Reference

BastionVault provides the `bvault` command-line tool for interacting with a running server. The CLI is compatible with HashiCorp Vault's command structure.

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
bvault server --config /path/to/config.hcl
~~~

| Option | Description |
|--------|-------------|
| `--config` | Path to configuration file or directory (required) |
| `--log-file` | Path to log file |
| `--log-level` | Log verbosity (default: `warn`) |

## status

Print the seal status of the vault.

~~~bash
bvault status
bvault status --format=json
~~~

Returns the sealed state, number of key shares, threshold, and unseal
progress, plus the storage cluster mode (`single` vs `clustered`), the
storage backend kind and -- when clustered -- this node's Raft id, whether
it is the leader, and cluster health.

Servers up to and including 0.41.18 reported `Cluster Mode single` /
`Storage Type file` even on a healthy hiqlite cluster, and
`bvault cluster leader` reported `Is Leader: true` on every node: the
cluster fields were compiled out of the shipped binary. Read those fields
from 0.41.19 onward, or from the storage engine's own logs.

## operator init

Initialize a new vault. With the default Shamir seal, generates the root key and splits it
using Shamir's Secret Sharing; both flags are required. With an HSM seal (auto-unseal), run
it bare — the root key is wrapped under the HSM and no unseal keys are produced.

~~~bash
bvault operator init                                  # HSM (auto-unseal) vault
bvault operator init --key-shares=5 --key-threshold=3 # Shamir-sealed vault
~~~

| Option | Description |
|--------|-------------|
| `--key-shares` | Number of key shares to generate (required for Shamir; omit for HSM) |
| `--key-threshold` | Number of shares required to unseal (required for Shamir; omit for HSM) |

Returns a list of unseal keys (empty for an HSM seal) and a root token. Store these securely.

## operator unseal

Provide an unseal key share. Must be called enough times to meet the threshold.

~~~bash
bvault operator unseal
bvault operator unseal 7df5ff90cd9417e04cbb9f6db65e0b16ce265d5108fd07e45bdae1a35bf5da6a
~~~

If the key is not provided as an argument, you will be prompted for it.

## operator seal

Seal the vault. All secrets become inaccessible until it is unsealed again.

~~~bash
bvault operator seal
~~~

## read

Read data from a path.

~~~bash
bvault read secret/my-secret
bvault read --field=password secret/my-secret
bvault read --format=json secret/my-secret
bvault read --env prod secret/apps/netrisk/db
~~~

| Option | Description |
|--------|-------------|
| `--field` | Print only the specified field value |
| `--env` | KV v2 environment selector — returns the base values merged with this environment's overrides. Required when the secret's policy lists `env` under `required_parameters`. See [Per-environment KV v2](kv-environments.md). |

## write

Write data to a path.

~~~bash
bvault write secret/my-secret foo=bar
bvault write secret/my-secret password=@/path/to/file
bvault write secret/my-secret data=-
bvault write --env prod secret/apps/netrisk/db host=db.prod.internal
~~~

Values can be specified as:
- `key=value` — literal value
- `key=@/path/to/file` — read value from a file
- `key=-` — read value from stdin

| Option | Description |
|--------|-------------|
| `--env` | KV v2 — write these `key=value` pairs as overrides for this environment only; the base values and other environments are preserved. See [Per-environment KV v2](kv-environments.md). |

## delete

Delete data at a path.

~~~bash
bvault delete secret/my-secret
~~~

## list

List keys at a path.

~~~bash
bvault list secret/
bvault list --format=json auth/
~~~

## login

Authenticate to BastionVault and obtain a token.

~~~bash
# Token auth (default)
bvault login s.my-token-value

# Username/password
bvault login --method=userpass username=admin password=secret

# Certificate
bvault login --method=cert --client-cert=client.crt --client-key=client.key
~~~

| Option | Description |
|--------|-------------|
| `--method` | Auth method: `token` (default), `userpass`, `cert` |
| `--path` | Mount path of the auth method (defaults to method name) |
| `--no-print` | Do not display the token after login |

## auth enable

Enable an authentication method.

~~~bash
bvault auth enable userpass
bvault auth enable --path=my-approle --description="App authentication" approle
~~~

| Option | Description |
|--------|-------------|
| `--path` | Mount path (defaults to the method type) |
| `--description` | Human-readable description |

## auth disable

Disable an authentication method. All tokens from this method are revoked.

~~~bash
bvault auth disable userpass/
~~~

## auth list

List all enabled authentication methods.

~~~bash
bvault auth list
bvault auth list --format=json
~~~

## auth move

Move an authentication method to a different path.

~~~bash
bvault auth move approle/ new-approle/
~~~

## policy write

Create or update a policy from a file.

~~~bash
bvault policy write my-policy policy.hcl
bvault policy write my-policy -    # read from stdin
~~~

## policy read

Read a policy by name.

~~~bash
bvault policy read my-policy
~~~

## policy delete

Delete a policy by name. The `default` and `root` policies cannot be deleted.

~~~bash
bvault policy delete my-policy
~~~

## policy list

List all policies.

~~~bash
bvault policy list
~~~

## secrets enable

Enable a secrets engine.

~~~bash
bvault secrets enable kv
bvault secrets enable --path=kv-v2 --version=2 kv
bvault secrets enable --max-lease-ttl=30m --path=short-lived kv
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
bvault secrets disable kv/
~~~

## secrets list

List all enabled secrets engines.

~~~bash
bvault secrets list
bvault secrets list --format=json
~~~

## secrets move

Move a secrets engine to a different path.

~~~bash
bvault secrets move secret/ generic/
~~~

## mcp

Give AI assistants scoped, audited access to BastionVault over the Model Context
Protocol. The operator guide is [`mcp.md`](mcp.md).

```bash
bvault mcp pair --client-name <name> [--transport stdio|uds|loopback-http]
bvault mcp serve [--stdio | --socket <path> | --listen 127.0.0.1:<port>]
bvault mcp pairings list
bvault mcp pairings revoke <id>
bvault mcp token --app <name> [--ttl-secs N] [--policies a,b]
bvault mcp catalogue
```

- `pair` needs an interactive terminal (a non-interactive environment cannot
  pair). It asks for the path scope, tools, and whether the client may reveal
  values or make changes. For `--transport loopback-http` it prints a pairing
  token once.
- `serve` runs the local MCP server. The three transports are mutually
  exclusive; stdio is the default. `--listen` accepts only a loopback address
  (`0.0.0.0:…` is a usage error), and `--socket` creates an owner-only socket.
  A client that is not paired, or a call that needs confirmation, is refused when
  there is no terminal to ask. `--allowed-origin` (repeatable) admits a browser
  origin on the loopback HTTP transport; the default admits none.
- `pairings revoke` removes the pairing locally and revokes its tokens on the
  vault; it exits non-zero if the vault could not be reached.
- `token --app` exchanges the current login for an MCP-bound token for a
  registered MCP app and prints it (`--format json`, `--field client_token`). The
  token is never persisted.
- `catalogue` prints every tool and the catalogue hash used by
  `sys/mcp/config`'s `catalogue_pin`. No vault is contacted.
- `--pairings-file` (env `BVAULT_MCP_PAIRINGS_FILE`) overrides the pairing store
  location, `$XDG_CONFIG_HOME/bvault/mcp-pairings.json` by default.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Error |
| 2 | Insufficient data or parameters |
