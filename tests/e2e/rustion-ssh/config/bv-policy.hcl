# Minimum admin policy the e2e operator needs to drive the
# Rustion-mediated session flow end-to-end.
#
# Bound to the test root token by run.sh on first start.

# Master signing-cert + Rustion target registry — admin scope.
path "rustion/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# System health + mount list (for the GUI bootstrap + the e2e
# driver's "wait for /v1/sys/health" loop).
path "sys/health" {
  capabilities = ["read"]
}
path "sys/mounts" {
  capabilities = ["read", "list"]
}
