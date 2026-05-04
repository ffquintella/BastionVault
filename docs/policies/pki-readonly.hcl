# pki-readonly — view-only access to a PKI mount.
#
# This role can read certs, issuers, roles, and the CRL. It cannot
# issue, sign, revoke, or export anything. Pair it with a separate
# role for the lifecycle operations the operator owns.
#
# Apply via: bv-cli policy write pki-readonly @docs/policies/pki-readonly.hcl
#
# Adjust the `pki/` prefix if your mount lives elsewhere (e.g.
# `secret-pki/`, `tenant-a-pki/`).

# Cert / issuer / role / chain reads.
path "pki/cert/*" {
  capabilities = ["read", "list"]
}
path "pki/certs" {
  capabilities = ["list"]
}
path "pki/issuer/*" {
  capabilities = ["read", "list"]
}
path "pki/issuers" {
  capabilities = ["list"]
}
path "pki/roles" {
  capabilities = ["list"]
}
path "pki/role/*" {
  capabilities = ["read"]
}

# CA cert + chain reads (public material).
path "pki/ca" {
  capabilities = ["read"]
}
path "pki/ca_chain" {
  capabilities = ["read"]
}
path "pki/cert/ca_chain" {
  capabilities = ["read"]
}

# CRL reads.
path "pki/crl" {
  capabilities = ["read"]
}
path "pki/issuer/+/crl" {
  capabilities = ["read"]
}

# Explicitly DENY every export path. The path wildcards above don't
# cover `*/export` (Vault's wildcards are non-recursive past `/`),
# but a defence-in-depth deny-list keeps the role's intent obvious
# even when the wildcard semantics shift.
path "pki/cert/+/export" {
  capabilities = ["deny"]
}
path "pki/issuer/+/export" {
  capabilities = ["deny"]
}
