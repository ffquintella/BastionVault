# Minimal single-node BV config for the connect-only e2e verification.
storage "file" {
  path = "/var/lib/bastion-vault/data"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
api_addr  = "http://0.0.0.0:8200"
log_level = "info"
