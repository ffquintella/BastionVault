# Node 2 of the 3-node cluster. See node1.hcl for the field-by-field
# explanation; this file differs only in `node_id` and `api_addr`.

storage "hiqlite" {
  data_dir         = "/var/lib/bvault/data"
  node_id          = 2
  secret_raft      = "change_me_shared_raft"
  secret_api       = "change_me_shared_api_"
  listen_addr_api  = "0.0.0.0:8220"
  listen_addr_raft = "0.0.0.0:8210"
  nodes = [
    "1:bv-1:8210:bv-1:8220",
    "2:bv-2:8210:bv-2:8220",
    "3:bv-3:8210:bv-3:8220",
  ]
}

listener "tcp" {
  address       = "0.0.0.0:8300"
  tls_disable   = false
  tls_cert_file = "/etc/bvault/tls/server.crt"
  tls_key_file  = "/etc/bvault/tls/server.key"
}

api_addr  = "https://bv-2:8300"
log_level = "info"
