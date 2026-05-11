# BastionVault DEVELOPMENT-ONLY configuration.
#
# Uses hiqlite storage in single-node mode with no replication.
# TLS is disabled for local development convenience.
# Do NOT use in production — see config/single-node.hcl or config/ha-cluster.hcl.
#
# Start with: bvault server --config config/dev.hcl

storage "hiqlite" {
  data_dir    = "/tmp/bastion_vault/data"
  node_id     = 1
  secret_raft = "dev_raft_secret_1"
  secret_api  = "dev_api_secret_16"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = true
}

api_addr   = "http://127.0.0.1:8200"
log_level  = "debug"
log_format = "{date} {req.path}"
pid_file   = "/tmp/bastion_vault.pid"

# Structured on-disk logs. Writes three files under `log_dir`:
#   operations.log — every record at or above `log_level`
#   security.log   — seal/unseal, failed logins, denied policies
#   audit.log      — auto-registered audit device, one JSON line per request
# Each file is size-rotated in-process: when it hits `log_rotate_size_mb`,
# it's renamed to `<name>.1`, prior `.1` shifts to `.2`, etc., keeping
# `log_rotate_keep` historical copies.
log_dir             = "/tmp/bastion_vault/logs"
log_to_stderr       = true
log_rotate_size_mb  = 100
log_rotate_keep     = 5
