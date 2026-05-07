# Node 1 of a 3-node Hiqlite cluster. Mounted at /etc/bvault/config.hcl
# inside the container. The other two nodes use sibling files
# (node2.hcl, node3.hcl) that differ only in `node_id` and the
# self-advertised hostname inside `nodes`.
#
# Replace `change_me_*` secrets before bringing the cluster up. The
# image rejects placeholder secrets via config validation so an
# unmodified bundle fails loudly.

storage "hiqlite" {
  data_dir         = "/var/lib/bvault/data"
  node_id          = 1
  secret_raft      = "change_me_shared_raft"
  secret_api       = "change_me_shared_api_"
  listen_addr_api  = "0.0.0.0:8220"
  listen_addr_raft = "0.0.0.0:8210"

  # Peer list. Each entry is `id:raft_host:raft_port:api_host:api_port`.
  # Hostnames resolve through the compose network so the Docker / Podman
  # DNS service brings the peers up at `bv-{1,2,3}` regardless of the
  # underlying IP assignments.
  nodes = [
    "1:bv-1:8210:bv-1:8220",
    "2:bv-2:8210:bv-2:8220",
    "3:bv-3:8210:bv-3:8220",
  ]

  # PQC-friendly Rustls (X25519MLKEM768) is the default. Mount real
  # mTLS material at /etc/bvault/tls/ to use it; the auto-generated
  # self-signed certs the image falls back to are NOT appropriate for
  # production HA — they're per-pod, so cross-node verification fails.
  # tls_raft_cert = "/etc/bvault/tls/raft.crt"
  # tls_raft_key  = "/etc/bvault/tls/raft.key"
  # tls_api_cert  = "/etc/bvault/tls/api.crt"
  # tls_api_key   = "/etc/bvault/tls/api.key"
}

listener "tcp" {
  address       = "0.0.0.0:8300"
  tls_disable   = false
  tls_cert_file = "/etc/bvault/tls/server.crt"
  tls_key_file  = "/etc/bvault/tls/server.key"
}

api_addr  = "https://bv-1:8300"
log_level = "info"
