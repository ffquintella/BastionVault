# Prometheus scraper identity.
#
# `GET /metrics` is authorization-gated. A scraper running off-host — i.e.
# one that is neither loopback nor a configured cluster node, and is not
# covered by `metrics { allow_unauthenticated_cidrs = [...] }` — must
# present a token carrying this grant.
#
#   bvault policy write metrics-scraper docs/policies/metrics-scraper.hcl
#   bvault write auth/token/create policies=metrics-scraper period=768h
#
# The token is scoped to telemetry only: it reads no secret, mounts
# nothing, and cannot enumerate the vault.

path "sys/metrics" {
  capabilities = ["read"]
}
