# BastionVault runtime image for the e2e docker-compose harness
# (tests/e2e/rustion-ssh/). Multi-stage:
#
#   stage 1 (builder): debian:bookworm-slim + rust stable, cargo
#                      build --release --bin bvault
#   stage 2 (runtime): distroless gcr.io/distroless/cc-debian12 with
#                      the bvault binary + a minimal /etc/bastion-vault
#                      layout the e2e configs bind-mount into
#
# Phase 3.2 of features/rustion-integration.md. Built without
# optional features (no Hiqlite cluster, no PKI cluster signer, no
# MySQL) — the e2e driver only needs the rustion mount + the policy
# store. Operators who want the full feature set use the Cargo
# workspace directly; this image is scoped to the integration test.

ARG RUST_VERSION=1.82
FROM rust:${RUST_VERSION}-bookworm AS builder

WORKDIR /build

# Cache deps separately from the source so a code-only change reuses
# the dependency layer. The first COPY is just the manifest set.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY gui/src-tauri/Cargo.toml ./gui/src-tauri/Cargo.toml
# Note: `plugins-ext/` is excluded from the Cargo workspace (and from the
# Docker build context via .dockerignore), so it is intentionally not copied.

# Source tree + build. The gui crate is in the workspace but its
# bastion-vault-gui binary needs the Tauri tooling — we explicitly
# build only `bvault` so the runtime stage stays slim.
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/build/target \
    cargo build --release --bin bvault \
    && cp target/release/bvault /usr/local/bin/bvault

# Runtime stage — distroless cc-debian12 keeps the attack surface
# small. The bvault binary is dynamically linked against glibc +
# libgcc which both ship in cc-debian12.
FROM gcr.io/distroless/cc-debian12 AS runtime

COPY --from=builder /usr/local/bin/bvault /usr/local/bin/bvault

# Operator bootstrap script for the Rustion master keypair. POSIX sh
# (runs under busybox ash). The e2e distroless image has no shell by
# default — copy the script out with `docker cp` and run from the
# host, or layer a shell-bearing image on top for in-container use.
COPY --chmod=0755 scripts/rustion-master-bootstrap.sh /usr/local/bin/rustion-master-bootstrap.sh

# Default config + data directories. The e2e compose file
# bind-mounts ./var/bv into /var/lib/bastion-vault so state survives
# `docker compose down`.
VOLUME ["/var/lib/bastion-vault"]
WORKDIR /var/lib/bastion-vault

EXPOSE 8200 8201

# NOTE: no auto-init env var. The server always starts sealed +
# uninitialised; the e2e driver (tests/e2e/rustion-ssh/run.sh) performs
# init + unseal over the API. (An earlier revision set an unread
# `BASTION_VAULT_LOCAL_DEV=1` here, implying an auto-init path that no
# server code ever honoured — removed to avoid the false promise.)
ENV VAULT_LOG_LEVEL=info

ENTRYPOINT ["/usr/local/bin/bvault"]
CMD ["server", "--config", "/etc/bastion-vault/config.toml"]
