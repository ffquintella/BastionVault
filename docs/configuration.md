# Configuration Reference

BastionVault is configured using HCL or JSON files. Pass the config file path to the server with `--config`.

~~~bash
bvault server --config /etc/bvault/config.hcl
~~~

You can also pass a directory; all `.hcl` and `.json` files in it are merged,
in file-name order. Each file must still declare exactly one `storage` and one
`listener` block. When merging:

- a scalar set in a later file (`log_level`, `api_addr`, `pid_file`, …)
  replaces the earlier value; `listener`, `storage` and `hsm` blocks are
  combined by label; a later `dos` block replaces an earlier one whole;
- the `mcp` block (including `brokered_sessions`) must be declared in **exactly
  one** file, which supplies the whole block. A second file declaring `mcp` —
  even an empty `mcp {}` — refuses to start, naming both files. It is never
  merged field by field: a later file could not switch a boolean back off,
  and a destination allow-list would be widened or replaced depending on file
  order.

## Minimal Example

~~~hcl
storage "file" {
  path = "./vault/data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = true
}

api_addr  = "http://127.0.0.1:8200"
log_level = "info"
~~~

## Full Example

~~~hcl
storage "file" {
  path = "/var/lib/bvault/data"
}

listener "tcp" {
  address                            = "0.0.0.0:8200"
  tls_disable                        = false
  tls_cert_file                      = "/etc/bvault/tls/server.crt"
  tls_key_file                       = "/etc/bvault/tls/server.key"
  tls_client_ca_file                 = "/etc/bvault/tls/ca.pem"
  tls_require_and_verify_client_cert = false
  tls_min_version                    = "tls12"
  tls_max_version                    = "tls13"
}

api_addr       = "https://vault.example.com:8200"
log_level      = "info"
log_format     = "{date} {req.path}"
pid_file       = "/var/run/bvault.pid"
work_dir       = "/var/lib/bvault"
daemon         = true
daemon_user    = "bvault"
daemon_group   = "bvault"
barrier_type   = "chacha20-poly1305"
~~~

## Global Options

| Option | Default | Description |
|--------|---------|-------------|
| `api_addr` | | Address advertised for API requests |
| `log_level` | `warn` | Logging level: `trace`, `debug`, `info`, `warn`, `error` |
| `log_format` | | Log output format pattern |
| `pid_file` | | Path to PID file when running as a daemon |
| `work_dir` | `/tmp/bastion_vault` | Working directory for runtime data |
| `daemon` | `false` | Run as a background daemon (Linux/macOS only) |
| `daemon_user` | | System user to run the daemon as |
| `daemon_group` | | System group to run the daemon as |
| `barrier_type` | `chacha20-poly1305` | Storage encryption: `chacha20-poly1305` or `aes-gcm` |
| `mount_entry_hmac_level` | `none` | HMAC level for mount entries: `none`, `compat`, `high` |
| `collection_interval` | `15` | Prometheus metrics collection interval in seconds |
| `mounts_monitor_interval` | `5` | Interval in seconds for monitoring mount changes |

## Listener

Exactly one listener block is required. Currently only `tcp` is supported.

~~~hcl
listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = false
}
~~~

| Option | Default | Description |
|--------|---------|-------------|
| `address` | | IP address and port to bind to |
| `tls_disable` | `true` | Set to `false` to enable TLS |
| `tls_cert_file` | | Path to PEM-encoded server certificate (required when TLS is enabled) |
| `tls_key_file` | | Path to PEM-encoded server private key (required when TLS is enabled) |
| `tls_client_ca_file` | | Path to PEM-encoded CA certificate for client verification |
| `tls_disable_client_certs` | `false` | Disable client certificate validation entirely |
| `tls_require_and_verify_client_cert` | `false` | Require and verify client certificates (mTLS) |
| `tls_min_version` | `tls12` | Minimum TLS version: `tls12` or `tls13` |
| `tls_max_version` | `tls13` | Maximum TLS version: `tls12` or `tls13` |

TLS is provided by `rustls` (pure Rust). When TLS is enabled, both `tls_cert_file` and `tls_key_file` are required.

## Storage

Exactly one storage block is required.

### File

Local encrypted file storage. Best for development and single-node deployments.

~~~hcl
storage "file" {
  path = "./vault/data"
}
~~~

| Option | Default | Description |
|--------|---------|-------------|
| `path` | | Directory path for encrypted vault data |

### Hiqlite (HA)

Embedded Raft-based SQLite storage for high-availability clusters. This is the recommended backend for production HA deployments.

~~~hcl
storage "hiqlite" {
  data_dir         = "/var/lib/bvault/data"
  node_id          = 1
  secret_raft      = "change_me_shared_raft"
  secret_api       = "change_me_shared_api_"
  nodes            = [
    "1:10.0.0.11:8210:10.0.0.11:8220",
    "2:10.0.0.12:8210:10.0.0.12:8220",
    "3:10.0.0.13:8210:10.0.0.13:8220",
  ]
}
~~~

| Option | Default | Description |
|--------|---------|-------------|
| `data_dir` | | Directory for Raft logs, SQLite database, and snapshots |
| `node_id` | | Unique numeric ID for this node |
| `secret_raft` | | Shared secret for Raft consensus authentication (min 16 chars) |
| `secret_api` | | Shared secret for management API authentication (min 16 chars) |
| `nodes` | | Array of node definitions: `"id:raft_host:raft_port:api_host:api_port"` |
| `table` | `vault` | SQLite table name |
| `listen_addr_raft` | `0.0.0.0` | Raft listener bind address |
| `listen_addr_api` | `0.0.0.0` | Management API listener bind address |
| `port_raft` | `8210` | Raft consensus port |
| `port_api` | `8220` | Management API port |
| `tls_raft_disable` | `false` | Disable TLS on Raft channel (not recommended) |
| `tls_api_disable` | `false` | Disable TLS on management API channel (not recommended) |
| `tls_raft_cert` | | Path to custom TLS certificate for Raft (auto-generated if omitted) |
| `tls_raft_key` | | Path to custom TLS private key for Raft (auto-generated if omitted) |
| `tls_api_cert` | | Path to custom TLS certificate for API (auto-generated if omitted) |
| `tls_api_key` | | Path to custom TLS private key for API (auto-generated if omitted) |

By default, both Raft and API channels use TLS with auto-generated self-signed certificates, providing post-quantum encryption (X25519MLKEM768 hybrid key exchange) for all inter-node traffic. Peer authentication is handled by the shared secrets (`secret_raft`/`secret_api`), while TLS provides confidentiality. Set `tls_raft_disable`/`tls_api_disable` to `true` only for development or testing.

#### Upgrading from hiqlite 0.14 (BastionVault releases before hiqlite 0.15.3)

The embedded hiqlite moved from 0.14 to **0.15.3**, which changed the Raft wire
format and the cache WAL. **A rolling upgrade is not possible**: a 0.15 node
cannot talk to a 0.14 node, and a 0.15 node started over a 0.14 cache WAL
refuses to start ("The Cache cleanup must be done as mentioned in the
changelog"). Plan a short full-cluster downtime:

1. Take a backup (`POST /v1/sys/backup`) while the old cluster is healthy.
2. Stop **every** node. None may run the old version while any node starts the
   new one.
3. On every node, clear the hiqlite **cache** (BastionVault uses it for
   distributed locks) — either
   - delete `<data_dir>/logs_cache/` and `<data_dir>/state_machine_cache/`, or
   - start the node once with `HQL_CACHE_WAL_AUTO_MIGRATE=true` in its
     environment: hiqlite then checks that no configured peer still runs the old
     version and clears the cache itself (it refuses to start if one does).
     Remove the variable afterwards.

   Do **not** delete `<data_dir>/logs/` or `<data_dir>/state_machine/`: they
   hold the vault data and are compatible. Deleting the cache by hand skips
   hiqlite's old-peer check, so step 2 is then entirely on you.
4. Start the nodes on the new version and check `bvault status` /
   `sys/health` for a healthy leader.

`HQL_CACHE_WAL_FORCE_MIGRATE=true` forces the cleanup even on a node already
started on 0.15; use it only to recover from a failed migration and remove it
immediately, since it clears the cache on every start. The BastionVault build
pins its hiqlite fork (`github.com/ffquintella/hiqlite`) to branch
`main-local` (upstream 0.15.3 plus the fork's deltas, listed in the root
`Cargo.toml`).

### MySQL (legacy, opt-in)

MySQL-backed storage using Diesel. Off by default — build with `--features storage_mysql` to enable. Kept for existing deployments not yet migrated to Hiqlite, which is now the recommended backend (see [Hiqlite (HA)](#hiqlite-ha) above).

~~~hcl
storage "mysql" {
  address  = "127.0.0.1:3306"
  username = "bvault"
  password = "secret"
  database = "bvault"
}
~~~

| Option | Default | Description |
|--------|---------|-------------|
| `address` | | MySQL server address and port |
| `username` | | Database username |
| `password` | | Database password |
| `database` | | Database name |

## HSM Seal (optional)

An optional `hsm "<backend>" { … }` block anchors the master key in a YubiHSM 2
(`yubihsm2`, build feature `hsm_yubihsm2`) or a software mock (`mock`, build
feature `hsm_mock`, dev/homolog only) and enables **auto-unseal**. At most one
block is allowed. With no block, the classic Shamir operator-unseal is used.

```hcl
hsm "yubihsm2" {
  connector         = "http://127.0.0.1:12345"   # or "usb"
  auth_key_id       = 3
  password          = "env:BVAULT_HSM_PASSWORD"   # plaintext rejected
  domains           = [1]
  pqc_key_cache_ttl = "60s"                        # "0" = strict per-op unwrap
  recovery          = "none"                       # or "shamir-ceremony"
  node_id           = "node-a"
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `connector` | | (yubihsm2) `yubihsm-connector` URL or `usb`. |
| `auth_key_id` | `1` | (yubihsm2) HSM auth-key object id. |
| `password` | | (yubihsm2) Auth credential; `env:VAR` supported, plaintext rejected. |
| `domains` | `[1]` | (yubihsm2) YubiHSM domains for BastionVault objects. |
| `state_path` | *(ephemeral)* | (mock) File backing the mock object store. |
| `node_id` | `$HOSTNAME` | Node identity for context strings / per-node keys. 1–128 characters of `[A-Za-z0-9._-]`. |
| `pqc_key_cache_ttl` | `60s` | Unwrapped-seed cache TTL; `0` disables caching. |
| `recovery` | `none` | `none` or `shamir-ceremony` (init-time only). `shamir-ceremony` is refused at `init` in the per-node topology and by `migrate-to-pool`; in a pool, init creates the recovery key and returns its shares (`recovery_shares` / `recovery_threshold`, default 5 / 3); see [docs/hsm.md](hsm.md#recovery-modes). |
| `topology` | `per-node` | `per-node` (one device per node) or `pool` (two devices shared by the cluster; see below). |
| `attestation_roots_file` | | (yubihsm2) PEM file holding the Yubico YubiHSM attestation root and intermediate certificates, which every YubiHSM 2 attestation is verified against (pool `bootstrap` and `member add`, per-node enrollment). Unset ⇒ every YubiHSM 2 attestation is refused. BastionVault neither ships nor downloads these certificates: get them from Yubico and check their fingerprints ([docs/hsm.md](hsm.md#yubico-attestation-trust-file)). Refused on the `mock` backend. |

> The mock backend has no hardware protection and refuses to start when
> `BVAULT_ENV=production`. See the [HSM guide](hsm.md) for the full workflow.

### HSM pool topology (`topology = "pool"`)

One or two devices serve the whole cluster ([HSM pool HA](../features/hsm-pool-ha.md),
T454): a cluster may start with one device (a *pool of one*, without redundancy)
and add the second later; it never has more than two
([starting with one HSM](hsm.md#starting-with-one-hsm-a-pool-of-one)). Pool nodes
authenticate with per-node credentials that node enrollment
delivers. A `yubihsm2` pool reaches its members through the HSM link and
attests them against `attestation_roots_file`; its device path is validated on
hardware by T454 phase 7 ([runbook](hsm.md#phase-7-hardware-validation-t454)),
which has not run yet.

```hcl
hsm "mock" {
  topology        = "pool"
  node_id         = "vault-3"
  recovery        = "none"          # required, explicitly, for pool init
  min_wrap_copies = 1               # 1 (default) | 2

  member "hsm-a" {
    serial     = "MOCK-A"
    state_path = "/var/lib/bastionvault/hsm-a.json"
  }
  member "hsm-b" {
    serial     = "MOCK-B"
    state_path = "/var/lib/bastionvault/hsm-b.json"
    # prefer   = true               # try this member first on every node
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `member "<name>"` | | One or two. One is a pool of one: init writes one member and one copy of each secret. `<name>` is 1–64 characters of `[A-Za-z0-9._-]`. |
| `member.serial` | | Required. The device serial; with the backend it forms the member's `hsm_id`. A new mock device is created with it. |
| `member.gateway` | | (yubihsm2) `https://` mTLS HSM gateway. Exactly one of `gateway` / `connector`. |
| `member.connector` | | (yubihsm2) Local `yubihsm-connector` URL or `usb`, on the node that hosts the device. |
| `member.state_path` | | (mock, required) File backing that mock device; the two must differ. |
| `member.prefer` | `false` | At most one member. Otherwise each node orders members by `SHA-256(node_id ‖ hsm_id)`. |
| `min_wrap_copies` | `1` | Copies a new key needs before it is stored, each on a distinct active member. `2` refuses key creation while a member is down, and is refused with one `member` block (a pool of one holds one copy). |
| `acknowledge_single_member_without_recovery` | `false` | Required, with `recovery = "none"`, to initialize a pool of one (or migrate onto one member, or retire down to one): it accepts that losing that one device makes the vault **unrecoverable**. Without it those operations are refused. Refused with `recovery = "shamir-ceremony"` and in a per-node block. Read when the operation runs; not stored. |
| `link { ca_file, cert_file, key_file }` | | (yubihsm2) This node's mTLS identity for the gateways; required when any member uses `gateway`. All three keys are required and each file must be readable at startup (validated, see below). |
| `credential_dir` | | (yubihsm2, required) Where this node's per-member credentials live. |
| `repair_rate` | `2` | Blob sets the repair job re-wraps per second, 1–100. |
| `device_audit` | `"drain"` | Device audit log drain (T454 phase 6): `"drain"` reads every member's log every 5 s and raises each command as `hsm.device_log`; `"forced"` also turns on the device's forced-audit option, so a member refuses commands (`LOG_FULL`) while its log is full until the drain catches up; `"off"` drains nothing and is refused when `BVAULT_ENV=production`. The drain needs the `bv-auditor` key, installed by `bvault operator hsm repair --run --admin …`. Mock only until T454 phase 7. |

Validation, all at startup:

- `password` and `auth_key_id` are refused (credentials come from
  `credential_dir`), and so are a top-level `connector` / `state_path`.
- The storage must have a real cluster lock: `hiqlite`, or a single-node `file`
  backend on a local path (dev and homolog). Any other storage, including a
  `file` backend with a cloud `target`, is a startup error naming it.
- After `init`, the **seal record** owns membership. A `member` block that
  disagrees with it (for example a different `serial`) is ignored with a `warn`
  naming the field; only where this node reaches the device (`connector`,
  `state_path`) is taken from config.
- Pool-only settings (`member`, `link`, `min_wrap_copies`, `repair_rate`,
  `device_audit`, `migrate_from`, `credential_dir`,
  `acknowledge_single_member_without_recovery`) in a per-node block are
  refused rather than ignored.
- Zero or three `member` blocks are refused. With two, init needs both
  devices reachable; it never falls back to a pool of one.
- `link` is needed only when a member is reached through `gateway`, and that
  is validated at startup: a `member` with `gateway` and no `link` block is
  refused with an error naming the member; a `link` block missing `ca_file`,
  `cert_file` or `key_file` is refused naming the missing key (and the member
  that needs it); and each `link` file must be a regular file the process can
  open, or startup is refused naming the key and the path. A `link` block that
  is present is checked even when no member uses `gateway` yet. A node on the
  HSM host that uses `connector = "http://127.0.0.1:<port>"` for every member
  it lists needs none; once a member on another host is added, that node needs
  a `link` block to reach it. If that member is named only in the seal record
  (added with `member add --gateway` and no `member` block on this node),
  startup validation cannot see it: reaching it fails instead, with the same
  error naming the member.

## Metrics Access (optional)

`GET /metrics` is authorization-gated. A scrape is served when **any** of the
following holds, checked in this order:

1. The **socket peer is cluster-local** — loopback, or an IP in the configured
   hiqlite `nodes` list. Same predicate as `sys/cluster-status`, judged on the
   TCP peer so no header can forge it. On by default.
2. The client IP is inside `allow_unauthenticated_cidrs`.
3. The request carries a **token with `read` on `sys/metrics`**.

Otherwise the endpoint returns `403`.

```hcl
metrics {
  allow_cluster_local         = true          # default
  allow_unauthenticated_cidrs = []            # e.g. ["10.20.0.0/16"]
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `allow_cluster_local` | `true` | Serve `/metrics` without a token to loopback and configured cluster nodes. Set `false` for strict token-only scraping. |
| `allow_unauthenticated_cidrs` | `[]` | Extra CIDRs that may scrape without a token. Matched against the trusted-proxy-aware client IP (see `BASTIONVAULT_TRUSTED_PROXIES`), so an untrusted `X-Forwarded-For` cannot forge a source. Unparseable entries are logged and dropped, never treated as a wildcard. |

A scraper on another host is expected to use a token. Create the policy and a
long-lived token for it:

```hcl
# metrics-scraper.hcl
path "sys/metrics" {
  capabilities = ["read"]
}
```

```bash
bvault policy write metrics-scraper metrics-scraper.hcl
```

Then point Prometheus at it:

```yaml
scrape_configs:
  - job_name: bastionvault
    metrics_path: /metrics
    authorization:
      credentials_file: /etc/prometheus/bastionvault.token
    static_configs:
      - targets: ["vault.example.org:8200"]
```

> A **sealed** node cannot validate tokens — the barrier that holds the token
> store is shut. Scraping a sealed node therefore only works over one of the IP
> allowances. Leaving `allow_cluster_local = true` is what keeps a node-local
> scrape working across a seal.

## MCP Access (optional)

Off by default. Serves the MCP endpoint `POST /v2/mcp` and the token exchange
`POST /v2/mcp/token`; see [`mcp.md`](mcp.md).

```hcl
mcp {
  enabled                  = true
  canonical_url            = "https://vault.example.com:8200/v2/mcp"
  allowed_origins          = []
  allow_plaintext_loopback = false
  max_request_bytes        = 262144
  tool_timeout_secs        = 30
}
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Serve the MCP routes; otherwise they answer 503 |
| `canonical_url` | — | The endpoint's public URL (RFC 8707 resource), advertised in the protected-resource metadata |
| `allowed_origins` | `[]` | Exact browser origins allowed to call `/v2/mcp`; empty admits only clients that send no `Origin` |
| `allow_plaintext_loopback` | `false` | Serve over a plaintext listener, only if that listener is loopback-only. Without it the routes require TLS |
| `max_request_bytes` | `0` (256 KiB) | Request body cap; 256 KiB is also the ceiling |
| `tool_timeout_secs` | `0` (30) | Per-call timeout |
| `require_hybrid_kex` | `false` | Not verifiable in this build: while `true`, `/v2/mcp` refuses to serve (503) rather than ignore it |

### `mcp.brokered_sessions` (optional)

The server switch and limits for agent sessions to resources
([spec](../features/mcp-brokered-sessions.md)). `ssh` opens sessions in a
build with the `mcp_sessions_ssh` feature, on by default (`bv_resource_ssh_exec`), `web` in
one with `mcp_sessions_web` (`bv_resource_web_fetch`); `rdp` is accepted and
has no tool yet. Off when absent; an old config parses unchanged. `GET v2/sys/mcp/config` reports
the block's `enabled` and `protocols`, and the destination list in force with
its source — `runtime`, `hcl` (this block, from an HCL or JSON file) or
`default` ([API](api.md#getpost-v2sysmcpconfig)). In a config directory the
block lives in the one file that declares `mcp` (see above).

```hcl
mcp {
  brokered_sessions {
    enabled                  = false
    protocols                = []   # subset of ["ssh", "web", "rdp"]
    allowed_target_cidrs     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
    max_concurrent           = 4
    rate_per_binding_per_min = 6
    call_timeout_secs        = 20
    rdp_call_timeout_secs    = 45
    max_output_bytes         = 65536
    ssh {
      cert_source_addresses = []
    }
  }
}
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Server switch; every session call also needs the runtime `sys/mcp/config.brokered_sessions_enabled` |
| `protocols` | `[]` | Protocols allowed; any other value refuses to load |
| `allowed_target_cidrs` | the list shown | Destination allow-list. A configured list **replaces** the default; `[]` allows nothing. Each entry must be `address/prefix` with no host bits set. Loopback, link-local (incl. `169.254.169.254`), multicast, unspecified, broadcast and the vault's own and cluster addresses stay denied whatever is listed: an overlapping entry is accepted with a startup warning on the `security` log. `sys/mcp/config` can replace this list at runtime |
| `max_concurrent` | `4` | Sessions open at once on this node, 1–32 |
| `rate_per_binding_per_min` | `6` | Session calls per pairing per minute on this node, 1–60 |
| `call_timeout_secs` / `rdp_call_timeout_secs` | `20` / `45` | Per-call timeouts (SSH and web / RDP), 1–120 |
| `max_output_bytes` | `65536` | Output returned to the model per call (SSH stdout and stderr together; a web fetch's page text), 1–262144 |
| `ssh.cert_source_addresses` | `[]` | The vault's egress addresses (address or CIDR) for a brokered certificate's `source-address`; empty omits it |

A value out of range, an unknown protocol or an invalid entry refuses to
start, naming the key and entry. Limits are in memory and per node.

## Audit Retention (runtime setting)

How long the replicated audit stores keep records is **not** an HCL option: it
is a cluster-wide runtime setting stored (encrypted, replicated) in the barrier,
so every node applies the same value whichever one is the Raft leader. Read and
change it with the sudo-gated `v2/sys/audit-retention` endpoint
([API reference](api.md#audit-trail-retention-and-dashboard-statistics)):

~~~bash
curl -H "X-Vault-Token: $ROOT" https://vault:8200/v2/sys/audit-retention
curl -H "X-Vault-Token: $ROOT" -X POST -d '{"retention_days": 90}' https://vault:8200/v2/sys/audit-retention
curl -H "X-Vault-Token: $ROOT" -X POST -d '{"enabled": false}'     https://vault:8200/v2/sys/audit-retention
~~~

| Setting | Default | Description |
|--------|---------|-------------|
| `retention_days` | `365` | Records older than this many days are deleted. 1–36500; `0` is refused. |
| `enabled` | `true` | `false` keeps every audit record forever. |

> **Upgrading deletes audit records older than a year.** Retention is on by
> default (365 days). A deployment that has never set it runs on the default,
> and the first run after the upgrade permanently deletes every audit record in
> the stores below that is older than 365 days. The endpoint only exists once
> the new version runs, so you cannot set it beforehand; instead the first run
> waits for the first 00:00 UTC **at least 24 hours** after the upgraded leader
> starts. Within that window, if you need longer retention:
>
> ~~~bash
> curl -H "X-Vault-Token: $ROOT" -X POST -d '{"retention_days": 3650}' https://vault:8200/v2/sys/audit-retention
> # or keep everything:
> curl -H "X-Vault-Token: $ROOT" -X POST -d '{"enabled": false}' https://vault:8200/v2/sys/audit-retention
> ~~~
>
> Every node logs a `security` warning at startup while the default applies,
> naming the time of the next run, and `GET v2/sys/audit-retention` reports
> `source: "default"` and `next_run_at`. Take a backup (`sys/backup`) before
> upgrading if in doubt.

- **Schedule:** daily at **00:00 UTC**, on the Raft leader only (the single node
  when not clustered). After an install or upgrade the first run is the first
  00:00 UTC at least 24 hours away; a node that was down at midnight runs once
  when it is back.
- **Clock check:** a run deletes nothing (`outcome: "refused"`) when the
  runner's clock is more than 2 days past the newest record in any pruned
  store — a clock that jumped ahead would otherwise move the cutoff and delete
  early. A deployment idle for that long just waits for new audit records.
- **Stores pruned:** `access-audit`, `denial-audit`, `login-audit`,
  `identity/user-audit`, `sharing/history`, `files-audit`, `ssh-sign-audit`,
  `ssh-ca-audit` follow `retention_days`. Policy, identity-group and
  asset-group change histories are kept, and the hash-chained `audit.log` file
  is governed by `log_rotate_size_mb` / `log_rotate_keep` instead.
- **MCP session transcripts** (`mcp-session-transcripts`, the commands an
  agent ran through brokered sessions and their output) have a **fixed
  30-day** rule that this setting can neither shorten nor lengthen: they are
  deleted at the first permitted daily run after 30 days even with
  `enabled: false`, `retention_days = 3650`, or an unreadable setting. The
  clock check still applies to them. `GET v2/sys/audit-retention` lists each
  store's rule under `store_rules`.
- **Load:** deletes go out in batches of 500 with a 50 ms pause, oldest first.
- **Observability:** one line per store on the `security` log (counts and the
  cutoff, never record contents) and the `last_run` report on the endpoint.
- If the stored setting cannot be read, the run deletes no audit record and
  reports `outcome: "failed"` (the transcripts' fixed rule still applies);
  write the setting again (both fields) to repair it.

The Dashboard's audit statistics are recomputed by the same background job
every 10 minutes; there is nothing to configure.

## Environment Variables

Configuration can also be influenced by environment variables:

| Variable | Description |
|----------|-------------|
| `VAULT_ADDR` / `RUSTY_VAULT_ADDR` | Default server address for the CLI |
| `VAULT_TOKEN` | Authentication token |
| `VAULT_CACERT` | Path to CA certificate for server verification |
| `VAULT_CAPATH` | Path to directory of CA certificates |
| `VAULT_CLIENT_CERT` | Path to client certificate for mTLS |
| `VAULT_CLIENT_KEY` | Path to client private key for mTLS |
| `VAULT_TLS_SERVER_NAME` | TLS SNI server name |
| `VAULT_SKIP_VERIFY` | Skip TLS certificate verification |
| `VAULT_LOG_LEVEL` | Override log level |
| `VAULT_FORMAT` | Default output format (`table`, `json`, `yaml`) |
