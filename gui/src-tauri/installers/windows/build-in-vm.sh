#!/usr/bin/env bash
#
# Build the BastionVault GUI Windows .msi (x64) in a DISPOSABLE Windows 11
# ARM64 VM managed by Tart (https://tart.run) — the Multipass-equivalent for
# Apple Silicon, using Apple's Virtualization.framework.
#
# Windows cannot be built in a container (there is no Windows-container
# runtime under macOS/Linux emulation), and x64 Windows only runs under slow
# QEMU emulation on Apple Silicon. So we run a NATIVE, fast ARM64 Windows 11
# guest and cross-compile the app to x86_64-pc-windows-msvc, producing an x64
# .msi. See README.md for the one-time base-image build.
#
# Flow (fully disposable — the ephemeral VM is always deleted on exit):
#   1. clone the prebuilt toolchain base image → an ephemeral VM
#   2. boot it headless, sharing the repo (read-only) + an output dir (rw)
#   3. `tart exec` the in-VM build.ps1 (cross-compiles + bundles the .msi)
#   4. the .msi lands in the shared output dir on the host
#   5. stop + delete the ephemeral VM (trap, always runs)
#
# Env knobs:
#   WIN_BUILDER_IMAGE   base image name        [bastionvault-win11-builder]
#   GUI_BUNDLE_FEATURES cargo features         [storage_hiqlite,ssh_pqc]
#   WIN_VM_BOOT_TIMEOUT seconds to wait for the guest agent   [300]
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# repo root: installers/windows -> src-tauri -> gui -> root
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

BASE_IMAGE="${WIN_BUILDER_IMAGE:-bastionvault-win11-builder}"
FEATURES="${GUI_BUNDLE_FEATURES:-storage_hiqlite,ssh_pqc}"
BOOT_TIMEOUT="${WIN_VM_BOOT_TIMEOUT:-300}"
# A unique, disposable clone name. $$ (PID) avoids Math.random-style helpers.
EPHEMERAL="bv-win-build-$$"
OUT_DIR="$REPO_ROOT/target/windows-vm"

command -v tart >/dev/null 2>&1 || die "tart not installed. Run: brew install cirruslabs/cli/tart"

# The base image carries the whole toolchain (Rust + x64 target, Node, VS
# Build Tools, WiX). It is built once via packer/ — see README.md.
if ! tart list --format json 2>/dev/null | grep -q "\"Name\":\"$BASE_IMAGE\""; then
    die "base image '$BASE_IMAGE' not found. Build it once with:
       cd $SCRIPT_DIR/packer && packer init . && \\
         packer build -var windows_iso=/path/to/Win11_ARM64.iso windows11-arm64.pkr.hcl
     (see README.md)."
fi

mkdir -p "$OUT_DIR"

echo "==> cloning $BASE_IMAGE -> $EPHEMERAL (disposable)"
tart clone "$BASE_IMAGE" "$EPHEMERAL"

# Always tear the ephemeral VM down, however we exit.
cleanup() {
    echo "==> tearing down $EPHEMERAL"
    tart stop "$EPHEMERAL" >/dev/null 2>&1 || true
    tart delete "$EPHEMERAL" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> booting $EPHEMERAL headless (repo shared read-only, output read-write)"
# --dir shares are surfaced in the guest by the Tart Guest Agent. build.ps1
# copies the source to a local disk before building (virtiofs is slow for a
# cargo target dir) and writes the finished .msi back to the 'bvout' share.
tart run --no-graphics \
    --dir="bvsrc:$REPO_ROOT:ro" \
    --dir="bvout:$OUT_DIR" \
    "$EPHEMERAL" &

# Wait for the guest agent to answer (Windows boot + agent start).
echo "==> waiting up to ${BOOT_TIMEOUT}s for the guest agent"
deadline=$(( $(date +%s) + BOOT_TIMEOUT ))
until tart exec "$EPHEMERAL" cmd /c "echo ready" >/dev/null 2>&1; do
    [ "$(date +%s)" -lt "$deadline" ] || die "guest agent did not come up within ${BOOT_TIMEOUT}s"
    sleep 5
done

echo "==> building the GUI .msi inside $EPHEMERAL (cross-compile -> x64)"
# build.ps1 ships in the base image at C:\bv\build.ps1 (staged by provision.ps1).
tart exec "$EPHEMERAL" powershell -NoProfile -ExecutionPolicy Bypass \
    -File 'C:\bv\build.ps1' -Features "$FEATURES"

echo ""
echo "==> .msi copied to target/windows-vm/:"
ls -lh "$OUT_DIR"/*.msi 2>/dev/null || die "no .msi found in $OUT_DIR — check the build output above"
