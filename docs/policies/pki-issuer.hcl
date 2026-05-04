# pki-issuer — can mint and revoke leaf certs but cannot export.
#
# Inherits the read surface from `pki-readonly` and adds:
#   * `pki/issue/<role>` — generate keypair + cert
#   * `pki/sign/<role>`  — sign a caller-supplied CSR
#   * `pki/sign-verbatim`
#   * `pki/revoke`
#
# Notably absent: every `*/export` path. A holder of this role can
# issue an X.509 cert tied to a freshly-generated managed key but
# cannot pull that key out of the vault — the engine returns the
# private key in the issue response only when called via this role
# AND the cert was issued with the engine's default `exportable=true`
# behaviour. To get the key out *after* issuance — for example to
# reinstall on a host that lost it — the operator switches to
# `pki-exporter` (separate role).
#
# Apply via: bv-cli policy write pki-issuer @docs/policies/pki-issuer.hcl

# Inherit the read surface.
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
path "pki/ca" {
  capabilities = ["read"]
}
path "pki/ca_chain" {
  capabilities = ["read"]
}
path "pki/crl" {
  capabilities = ["read"]
}
path "pki/issuer/+/crl" {
  capabilities = ["read"]
}

# Issuance + signing.
path "pki/issue/+" {
  capabilities = ["update"]
}
path "pki/sign/+" {
  capabilities = ["update"]
}
path "pki/sign-verbatim" {
  capabilities = ["update"]
}

# Lifecycle on existing certs.
path "pki/revoke" {
  capabilities = ["update"]
}

# CSR flow (operator generates a CSR locally and ships it to an
# external CA — `pki/csr/generate` is sometimes useful even for a
# pure-issuer role; keep it here so the same role can drive both
# directions of the workflow).
path "pki/csr/generate" {
  capabilities = ["update"]
}
path "pki/csr" {
  capabilities = ["list"]
}
path "pki/csr/+" {
  capabilities = ["read", "delete"]
}
path "pki/csr/+/set-signed" {
  capabilities = ["update"]
}

# Explicitly DENY every export path. Holders of this role MUST NOT
# pull cert / key bytes out of the vault — that's `pki-exporter`'s
# job, and the policy split lets the operator audit each role
# separately.
path "pki/cert/+/export" {
  capabilities = ["deny"]
}
path "pki/issuer/+/export" {
  capabilities = ["deny"]
}
