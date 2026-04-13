---
sidebar_position: 3
title: Configuration
---

# Configuration Reference

BastionVault is configured using HCL or JSON files. Pass the config file path to the server with `--config`.

~~~bash
bvault server --config /etc/bvault/config.hcl
~~~

You can also pass a directory; all `.hcl` and `.json` files in it will be merged.

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

### MySQL

MySQL-backed storage using Diesel.

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
