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
