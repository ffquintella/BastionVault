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
