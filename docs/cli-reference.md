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

## hsm-gateway

Run the HSM pool gateway on a host with a YubiHSM 2 (see
[features/hsm-pool-ha.md](../features/hsm-pool-ha.md)). It is not a vault: it has no
storage and no tokens. It listens with mutual TLS and forwards `POST /connector/api`
and `GET /connector/status` bodies verbatim to the `yubihsm-connector` on loopback,
which must never be exposed itself.

~~~bash
bvault hsm-gateway --config /etc/bastionvault/hsm-gateway.hcl
~~~

| Option | Env Variable | Description |
|--------|-------------|-------------|
| `--config` | | Path to the gateway's HCL file (required) |
| `--log-level` | `BVAULT_HSM_GATEWAY_LOG_LEVEL` | Log filter, e.g. `info` (default) or `info,bv_hsm_link=debug`; logs go to stderr |

~~~hcl
hsm_gateway {
  listen             = "0.0.0.0:8250"
  connector          = "http://127.0.0.1:12345"   # loopback IP literal only
  tls_cert_file      = "/etc/bastionvault/hsm-link/hsm-a.pem"
  tls_key_file       = "/etc/bastionvault/hsm-link/hsm-a.key"
  client_ca_file     = "/etc/bastionvault/hsm-link/ca.pem"
  allowed_clients    = ["vault-1", "vault-2", "vault-3"]   # node ids, DNS SAN match, exact
  max_rps_per_client = 50                                    # optional, 1-10000, default 50
}
~~~

| Field | Rule |
|-------|------|
| `listen` | `ip:port` to bind. |
| `connector` | `http://` on `127.0.0.1` (or another `127.x` / `[::1]`) with a port. Names, including `localhost`, are refused. |
| `tls_cert_file`, `tls_key_file` | The gateway's server certificate (chain) and key, PEM. Nodes verify it against their link CA and the gateway URL's host. |
| `client_ca_file` | CA that node link certificates must chain to. |
| `allowed_clients` | Non-empty, unique node ids (1–128 of `[A-Za-z0-9._-]`). A client certificate must carry exactly one of them as a DNS SAN; a certificate naming two is refused. |
| `max_rps_per_client` | Token bucket per client, burst of one second. |

Unknown fields, missing fields and a second `hsm_gateway` block are errors; the
command exits with the configuration-failure code before listening. Fixed limits: TLS
1.3 only, one request in flight per client (a second gets `429`), request body
3–3139 bytes, 5 s per connector exchange (`504`; other connector failures are `502`),
60 s idle connections, 128 open connections. It stops on Ctrl-C or SIGTERM. To revoke
a node, remove it from `allowed_clients` and restart the gateway.

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
| `--recovery-shares` | HSM pool with `recovery = "shamir-ceremony"` only: recovery shares to generate (default 5). Any other seal refuses it |
| `--recovery-threshold` | Recovery shares the recovery ceremony needs (default 3); give it with `--recovery-shares` |

Returns a list of unseal keys (empty for an HSM seal) and a root token. Store these securely.
The command calls `/v2/sys/init` whatever `--api-version` says (`v1/sys/init` is frozen and
cannot return recovery shares). An HSM pool with `recovery = "shamir-ceremony"` also returns `recovery_keys`: the recovery
shares, printed once and stored nowhere. They are not unseal keys; hand one to each holder
(see `operator hsm recover`).

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

## operator hsm

Inspect the HSM seal and run the HSM pool ceremonies (see
[docs/hsm.md](hsm.md) and [features/hsm-pool-ha.md](../features/hsm-pool-ha.md)).
Every verb but `status`, `provision` (local) and `bootstrap` (loopback, before init) needs a `sudo` token; they call the `v2/sys/hsm/*` routes.

~~~bash
bvault operator hsm status
bvault operator hsm members
bvault operator hsm member add <name> --bundle <file> [--gateway https://…] --admin <name>
bvault operator hsm member retire <name>
bvault operator hsm node add <node_id> --fingerprint <fp> --admin <member> [--admin <member>…]
bvault operator hsm node revoke <node_id> --admin <member> [--admin <member>…]
bvault operator hsm node list
bvault operator hsm repair [--run [--admin <member>…]]
# Pool setup: provision runs on the HSM host against the device; bootstrap runs
# on the init node (loopback) before `operator init`.
bvault operator hsm provision (--mock-state-path <file> --serial <s> | --connector <url>) --out <bundle.json> [--adopt] [--admin-password env:VAR] [--factory-password env:VAR]
bvault operator hsm bootstrap --bundle <member>=<file> [--bundle …] --admin <member> [--admin <member>…]
bvault operator hsm rotate-epoch --admin <member> [--admin <member>…]
bvault operator hsm migrate-to-pool   # loopback, with `migrate_from` configured, after bootstrap
# Both devices lost (sealed node, no token): shares, then the two new devices.
bvault operator hsm recover --member <name>=<bundle.json> [--member …] [--gateway <name>=https://…] --admin <name> [--admin …] [--share env:VAR …]
bvault operator hsm recover --reset   # discard the shares submitted so far
~~~

A pool may start with one device (a *pool of one*: one `member` block, one
`--bundle` to `bootstrap`) and gain the second with `member add`; `status`
then moves from `redundancy: "none"` to `"full"` after the repair that
promotes it. `member add` refuses a third device (a cluster has at most two):
`member retire` a failed one first. `member retire` refuses the last active
member. With `recovery = "none"`, `bootstrap`, `init` and a retire down to one
member are refused unless the node's `hsm` block sets
`acknowledge_single_member_without_recovery = true`
([docs/hsm.md](hsm.md#starting-with-one-hsm-a-pool-of-one)).

`recover` submits each share on its own (`--share env:VAR`, repeatable, or a
hidden TTY prompt per share until the threshold is reached; a literal share is
refused), then the new members and their admin credentials. It needs no token:
the server accepts it only on a sealed node while every pool member is
unreachable.

| Option | Description |
|--------|-------------|
| `--admin <member>` | Prompt on the TTY (no echo) for that member's `bv-admin` credential; repeat per member |
| `--admin <member>=env:VAR` | Read it from the environment variable `VAR` instead. Any other `=value` is refused: an argument would sit in the process list and the shell history |
| `--fingerprint` | The node's transport key fingerprint, as its log shows it; confirm it out of band |
| `--bundle` | The attestation bundle (JSON) that provisioning the device produced |
| `--run` | Run the repair job now instead of showing the last run. With `--admin`, it also applies pending revocations, promotes joining members and installs the `bv-auditor` key the device-log drain needs on each named member (`auditors_installed` in the report) |
| `--member <name>=<file>` | `recover`: a new device and its attestation bundle |
| `--share env:VAR` | `recover`: read one recovery share (hex) from `VAR`; repeat per share |
| `--reset` | `recover`: discard the shares this node holds for a running ceremony |

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
bvault mcp serve [--stdio | --socket <path> | --listen 127.0.0.1:<port>] [--namespace <ns>]
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
  origin on the loopback HTTP transport; the default admits none. On stdio and
  `--socket` it also accepts the `initialize` handshake of clients on MCP
  2025-03-26 to 2025-11-25, such as Claude Code; see
  [Clients on earlier MCP revisions](mcp.md#clients-on-earlier-mcp-revisions).
  Tokens are bound to your session's namespace; `--namespace <ns>` asks the
  vault to bind every token it mints to `<ns>` instead, which it accepts only
  for your own namespace, one beneath it from a child-visible sign-in, or one
  assigned to you (`mcp_namespace_not_permitted` otherwise). A malformed path is a usage
  error. See [Namespaces](mcp.md#namespaces).
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
