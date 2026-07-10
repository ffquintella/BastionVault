#!/usr/bin/env bash
#
# Build the BastionVault GUI .deb + .rpm inside an emulated amd64 Linux
# container (see Dockerfile in this directory). This lets a non-Linux host
# (e.g. an Apple-Silicon Mac) produce the Linux GUI installers that Tauri
# cannot cross-compile, by running the whole build in a real Linux/amd64
# userland under Docker Desktop's emulation.
#
# NOTE: emulated compilation is SLOW — the full GUI backend compile under
# QEMU/Rosetta can take the better part of an hour on the first run.
# Subsequent runs reuse the cached cargo registry + target volumes.
#
# Env knobs:
#   GUI_LINUX_BUILDER_IMAGE   image tag           [bastionvault-gui-linux-builder]
#   GUI_LINUX_PLATFORM        docker platform     [linux/amd64]
#   GUI_BUNDLE_FEATURES       cargo features      [storage_hiqlite,ssh_pqc]
#   REBUILD_IMAGE=1           force `docker build` even if the image exists
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# repo root is four levels up: installers/linux -> src-tauri -> gui -> root
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

IMAGE="${GUI_LINUX_BUILDER_IMAGE:-bastionvault-gui-linux-builder}"
PLATFORM="${GUI_LINUX_PLATFORM:-linux/amd64}"
FEATURES="${GUI_BUNDLE_FEATURES:-storage_hiqlite,ssh_pqc}"

command -v docker >/dev/null 2>&1 || die "docker not found."
docker info >/dev/null 2>&1 || die "docker daemon not running (start Docker Desktop)."

# Build the builder image (once, unless forced or missing).
if [ "${REBUILD_IMAGE:-0}" = "1" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "==> building builder image $IMAGE ($PLATFORM)"
    docker build --platform "$PLATFORM" -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"
else
    echo "==> reusing builder image $IMAGE (REBUILD_IMAGE=1 to rebuild)"
fi

echo "==> building GUI .deb/.rpm inside $IMAGE (emulated $PLATFORM — this is slow)"
# Named volumes keep the heavy compile I/O off the bind mount and out of
# the host tree:
#   *-cargo        cargo registry cache (dep downloads reused across runs)
#   *-node_modules shadows gui/node_modules so `npm ci` in the container
#                  does not overwrite the host's (darwin/arm64) install
#   *-target       CARGO_TARGET_DIR — emulated build objects, not on host
# Only the final bundles are copied back onto the bind mount, under
# target/linux-docker/, so they are reachable from the host.
docker run --rm --platform "$PLATFORM" \
    -v "$REPO_ROOT:/work" -w /work \
    -v bastionvault-gui-linux-cargo:/opt/cargo/registry \
    -v bastionvault-gui-linux-node_modules:/work/gui/node_modules \
    -v bastionvault-gui-linux-target:/target \
    -e CARGO_TARGET_DIR=/target \
    -e GUI_BUNDLE_FEATURES="$FEATURES" \
    "$IMAGE" \
    bash -euo pipefail -c '
        cd gui
        if [ -f package-lock.json ]; then npm ci; else npm install; fi
        npx tauri build --bundles deb,rpm -- --features "$GUI_BUNDLE_FEATURES"
        mkdir -p /work/target/linux-docker
        cp -av /target/release/bundle/deb /target/release/bundle/rpm /work/target/linux-docker/
    '

echo ""
echo "==> GUI bundles copied to target/linux-docker/:"
ls -lh "$REPO_ROOT"/target/linux-docker/deb/*.deb \
       "$REPO_ROOT"/target/linux-docker/rpm/*.rpm 2>/dev/null || true
