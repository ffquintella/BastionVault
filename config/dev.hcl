# BastionVault DEVELOPMENT-ONLY configuration.
#
# Uses the file backend with no TLS. Do NOT use in production.
# For production, use config/single-node.hcl or config/ha-cluster.hcl
# with the hiqlite storage backend.
#
# Start with: bvault server --config config/dev.hcl

storage "file" {
  path = "./vault/data"
}

listener "tcp" {
  address     = "127.0.0.1:8200"
  tls_disable = true
}

api_addr   = "http://127.0.0.1:8200"
log_level  = "debug"
log_format = "{date} {req.path}"
pid_file   = "/tmp/bastion_vault.pid"
