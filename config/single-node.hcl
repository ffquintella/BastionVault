# BastionVault single-node configuration with hiqlite storage.
#
# This is suitable for small deployments or staging environments.
# For production HA, use a multi-node configuration instead.
#
# Start with: bvault server --config config/single-node.hcl

storage "hiqlite" {
  data_dir    = "/var/lib/bvault/data"
  node_id     = 1
  secret_raft = "change_me_raft_16ch"
  secret_api  = "change_me_api_16chr"
}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = false
  tls_cert_file = "/etc/bvault/tls/server.crt"
  tls_key_file  = "/etc/bvault/tls/server.key"
  # Publish the serving cert so local `bvault` CLI calls trust it without
  # --tls-skip-verify or --ca-cert on every invocation. The CLI auto-loads
  # /etc/bvault/ca.pem and ~/.bvault/ca.pem (and $BVAULT_CACERT_AUTO).
  tls_publish_ca_path = "/etc/bvault/ca.pem"
}

api_addr   = "https://127.0.0.1:8200"
log_level  = "info"
pid_file   = "/var/run/bvault.pid"
