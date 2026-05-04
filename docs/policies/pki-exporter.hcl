# pki-exporter — read access + the export endpoints.
#
# This role can pull cert + (when the bound managed key was minted
# `exportable=true`) private-key bytes out of the vault via:
#   * `pki/cert/<serial>/export` — leaf, optionally with private key
#   * `pki/issuer/<ref>/export`  — issuer cert + chain (never key)
#
# The host enforces *three* gates beyond this policy on every export
# call:
#   1. ACL — this file. Holders of this role pass; others are refused
#      with a 403 before the handler runs.
#   2. `KeyEntry.exportable` — read-only flag pinned at managed-key
#      create / import time. Even root cannot flip it. If the key was
#      minted `exportable=false`, the export refuses unless …
#   3. … `mode=backup` is set, which bypasses (2) but only allows
#      encrypted formats (PKCS#12; lands in a follow-up). Today
#      backup mode + PEM / PKCS#7 is rejected by the host.
#
# Issuer keys are *always* refused for export — the
# `pki/issuer/<ref>/export` route doesn't accept `include_private_key`
# at all, regardless of policy or mode.
#
# Apply via: bv-cli policy write pki-exporter @docs/policies/pki-exporter.hcl

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

# Export endpoints — the differentiator vs pki-readonly / pki-issuer.
# Both routes are GET-shaped (`Operation::Read` server-side), so
# `read` is the right capability.
path "pki/cert/+/export" {
  capabilities = ["read"]
}
path "pki/issuer/+/export" {
  capabilities = ["read"]
}
