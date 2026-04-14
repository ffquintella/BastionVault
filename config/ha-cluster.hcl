# BastionVault HA cluster configuration with hiqlite storage.
#
# Deploy this config on each node, changing only node_id and listen addresses.
# A 3-node cluster is the recommended minimum for production HA.
#
# Node 1: bvault server --config config/ha-cluster.hcl
# Node 2: same config with node_id = 2, adjusted addresses
# Node 3: same config with node_id = 3, adjusted addresses

storage "hiqlite" {
  data_dir         = "/var/lib/bvault/data"
  node_id          = 1
  secret_raft      = "change_me_shared_raft"
  secret_api       = "change_me_shared_api_"
  listen_addr_api  = "0.0.0.0:8220"
  listen_addr_raft = "0.0.0.0:8210"
  nodes            = [
    "1:10.0.0.11:8210:10.0.0.11:8220",
    "2:10.0.0.12:8210:10.0.0.12:8220",
    "3:10.0.0.13:8210:10.0.0.13:8220",
  ]
}

listener "tcp" {
  address       = "0.0.0.0:8300"
  tls_disable   = false
  tls_cert_file = "/etc/bvault/tls/server.crt"
  tls_key_file  = "/etc/bvault/tls/server.key"
}

api_addr   = "https://10.0.0.11:8300"
log_level  = "info"
pid_file   = "/var/run/bvault.pid"
