#!/usr/bin/env bash
#
# Wrap the Tauri-built BastionVault.app into a distribution .pkg.
#
# Tauri's macOS bundler produces the .app (and a .dmg); Munki / Jamf / MDM
# want a .pkg. This wraps the .app with pkgbuild + productbuild so it
# installs into /Applications and can be pushed through management tooling.
#
# Invoked by `make gui-macos-pkg`. Configuration via the environment:
#
#   VERSION            product version (e.g. 0.27.0)                 [required]
#   APP_PATH           path to the built BastionVault.app            [required]
#   PKG_ARCH           arch label for the file name + hostArchitectures
#                      (arm64 | x86_64 | "arm64,x86_64" for universal2)
#                      [default: host arch]
#   OUTPUT_DIR         where the .pkg is written [default: target/pkg]
#   INSTALLER_IDENTITY "Developer ID Installer: <team>" to sign with;
#                      unset ⇒ unsigned pkg (notarisation happens in CI)
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

command -v pkgbuild     >/dev/null 2>&1 || die "pkgbuild not found (run on macOS)."
command -v productbuild >/dev/null 2>&1 || die "productbuild not found (run on macOS)."

: "${VERSION:?VERSION must be set}"
: "${APP_PATH:?APP_PATH must be set (path to BastionVault.app)}"
[ -d "$APP_PATH" ] || die "APP_PATH is not a directory: $APP_PATH"

PKG_ARCH="${PKG_ARCH:-$(uname -m)}"
OUTPUT_DIR="${OUTPUT_DIR:-target/pkg}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$OUTPUT_DIR"

# 1) Component package: install the .app into /Applications.
COMPONENT_PKG="$WORK/component.pkg"
pkgbuild \
    --component "$APP_PATH" \
    --identifier "com.bastionvault.gui" \
    --version "$VERSION" \
    --install-location "/Applications" \
    "$COMPONENT_PKG"

# 2) Distribution package for the Installer GUI / MDM, with the arch guard.
DIST="$WORK/distribution.xml"
sed -e "s/@VERSION@/$VERSION/g" -e "s/@HOSTARCH@/$PKG_ARCH/g" \
    "$SCRIPT_DIR/distribution.xml" > "$DIST"

# Sanitise the arch for the file name (universal2 for the combined slice).
FILE_ARCH="$PKG_ARCH"
case "$PKG_ARCH" in *,*) FILE_ARCH="universal2" ;; esac
OUT_PKG="$OUTPUT_DIR/BastionVault-$VERSION-$FILE_ARCH.pkg"

SIGN_ARGS=()
if [ -n "${INSTALLER_IDENTITY:-}" ]; then
    SIGN_ARGS=(--sign "$INSTALLER_IDENTITY")
    echo "==> signing with Developer ID Installer identity"
else
    echo "==> INSTALLER_IDENTITY not set — building an UNSIGNED pkg"
fi

# ${SIGN_ARGS[@]+...} guards the empty-array case under bash 3.2 (macOS).
productbuild \
    --distribution "$DIST" \
    --package-path "$WORK" \
    ${SIGN_ARGS[@]+"${SIGN_ARGS[@]}"} \
    "$OUT_PKG"

echo ""
echo "==> Built $OUT_PKG"
