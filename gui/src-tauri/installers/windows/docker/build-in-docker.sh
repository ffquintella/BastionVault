#!/usr/bin/env bash
#
# Build the BastionVault GUI Windows x64 installer inside Docker, with no
# Windows host and no Windows VM: `cargo-xwin` cross-compiles to
# `x86_64-pc-windows-msvc` and Tauri's NSIS bundler (Linux `makensis`)
# wraps it into `BastionVault_<version>_x64-setup.exe`.
#
# This produces an NSIS .exe, NOT an .msi. Tauri v2 compiles its WiX/MSI
# bundler in on Windows hosts only, so an .msi still needs the Tart VM path
# (../README.md) or a real Windows host. The .exe is a normal per-user/
# per-machine Windows installer with Start-menu and Add/Remove entries.
#
# Unlike the Linux .deb/.rpm container (../../linux/build-in-docker.sh),
# nothing here is emulated — the container runs at the host's native arch
# and cross-compiles, so an Apple Silicon Mac builds at full speed.
#
# Env knobs:
#   XWIN_ACCEPT_LICENSE=1     REQUIRED — see the licence note below
#   GUI_WIN_BUILDER_IMAGE     image tag        [bastionvault-gui-win-builder]
#   GUI_WIN_PLATFORM          docker platform  [host native]
#   GUI_BUNDLE_FEATURES       cargo features   [storage_hiqlite,ssh_pqc]
#   REBUILD_IMAGE=1           force `docker build` even if the image exists
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# repo root is five levels up: installers/windows/docker -> windows ->
# installers -> src-tauri -> gui -> root
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../../.." && pwd)"

IMAGE="${GUI_WIN_BUILDER_IMAGE:-bastionvault-gui-win-builder}"
FEATURES="${GUI_BUNDLE_FEATURES:-storage_hiqlite,ssh_pqc}"
# Default to the host's own architecture: the cross-compile targets x64
# Windows either way, so there is nothing to gain from emulating amd64 here
# (unlike the Linux .deb/.rpm path, which must run in an amd64 userland).
case "$(uname -m)" in
    arm64|aarch64) HOST_PLATFORM=linux/arm64 ;;
    x86_64|amd64)  HOST_PLATFORM=linux/amd64 ;;
    *)             die "unsupported host arch $(uname -m) — set GUI_WIN_PLATFORM explicitly" ;;
esac
PLATFORM="${GUI_WIN_PLATFORM:-$HOST_PLATFORM}"

# ── Microsoft CRT/SDK licence ──────────────────────────────────────────
#
# cargo-xwin downloads the Microsoft Visual C++ runtime headers/libs and
# the Windows SDK from Microsoft's own CDN, which is only permitted under
# the Visual Studio licence terms. Accepting those terms is the operator's
# call, not this script's, so the acceptance is NOT baked in: set
# XWIN_ACCEPT_LICENSE=1 yourself to state that you accept them.
#
#   https://www.visualstudio.com/license-terms/
if [ "${XWIN_ACCEPT_LICENSE:-}" != "1" ]; then
    cat >&2 <<'MSG'
ERROR: XWIN_ACCEPT_LICENSE=1 is required.

  Cross-compiling to x86_64-pc-windows-msvc needs Microsoft's Visual C++
  CRT and Windows SDK headers/libraries. cargo-xwin downloads them from
  Microsoft, and doing so requires accepting the Visual Studio licence
  terms: https://www.visualstudio.com/license-terms/

  That acceptance is yours to give, so re-run with it explicit:

      XWIN_ACCEPT_LICENSE=1 make gui-windows-nsis

  Prefer not to? Use the Tart VM path (real Windows, real .msi) instead —
  see gui/src-tauri/installers/windows/README.md.
MSG
    exit 1
fi

command -v docker >/dev/null 2>&1 || die "docker not found."
docker info >/dev/null 2>&1 || die "docker daemon not running (start Docker Desktop)."

# The GUI path-depends on the IronRDP fork via a submodule; a missing
# checkout fails deep inside the cross-compile instead of here.
[ -f "$REPO_ROOT/IronRDP/Cargo.toml" ] \
    || die "IronRDP submodule not checked out — run: git submodule update --init IronRDP"

if [ "${REBUILD_IMAGE:-0}" = "1" ] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
    echo "==> building builder image $IMAGE ($PLATFORM)"
    docker build --platform "$PLATFORM" -t "$IMAGE" -f "$SCRIPT_DIR/Dockerfile" "$SCRIPT_DIR"
else
    echo "==> reusing builder image $IMAGE (REBUILD_IMAGE=1 to rebuild)"
fi

echo "==> cross-compiling the GUI to x86_64-pc-windows-msvc in $IMAGE"
# Named volumes keep the heavy compile I/O off the bind mount and out of
# the host tree:
#   *-cargo        cargo registry cache (dep downloads reused across runs)
#   *-node_modules shadows gui/node_modules so `npm ci` in the container
#                  does not overwrite the host's (darwin/arm64) install
#   *-target       CARGO_TARGET_DIR — cross-compiled objects, not on host
#   *-xwin         the downloaded MSVC CRT + Windows SDK (~1 GB), so only
#                  the first run pays for it
# Only the finished installer is copied back onto the bind mount, under
# target/windows-docker/, so it is reachable from the host.
docker run --rm --platform "$PLATFORM" \
    -v "$REPO_ROOT:/work" -w /work \
    -v bastionvault-gui-win-cargo:/opt/cargo/registry \
    -v bastionvault-gui-win-node_modules:/work/gui/node_modules \
    -v bastionvault-gui-win-target:/target \
    -v bastionvault-gui-win-xwin:/opt/xwin \
    -e CARGO_TARGET_DIR=/target \
    -e XWIN_ACCEPT_LICENSE=1 \
    -e GUI_BUNDLE_FEATURES="$FEATURES" \
    "$IMAGE" \
    bash -euo pipefail -c '
        cd gui
        if [ -f package-lock.json ]; then npm ci; else npm install; fi
        npx tauri build \
            --runner cargo-xwin \
            --target x86_64-pc-windows-msvc \
            --bundles nsis \
            -- --features "$GUI_BUNDLE_FEATURES"
        mkdir -p /work/target/windows-docker
        cp -av /target/x86_64-pc-windows-msvc/release/bundle/nsis/*.exe \
               /work/target/windows-docker/
    '

echo ""
echo "==> GUI installer copied to target/windows-docker/:"
ls -lh "$REPO_ROOT"/target/windows-docker/*.exe 2>/dev/null || true
