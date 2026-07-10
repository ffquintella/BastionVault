#!/usr/bin/env bash
#
# Build the BastionVault CLI macOS installer package (.pkg).
#
# Produces a signed-if-configured, distribution-style .pkg that installs:
#
#   /usr/local/bin/bvault
#   /usr/local/share/man/man1/bvault.1.gz
#   /usr/local/etc/bash_completion.d/bvault
#   /usr/local/share/zsh/site-functions/_bvault
#
# The CLI installer bestows no privileges and registers no service — it is
# a plain file drop into /usr/local, matching the security posture in
# features/packaging-client-binaries.md.
#
# Invoked by `make macos-cli-pkg`. Configuration comes from the
# environment so the same script serves local builds and CI:
#
#   VERSION            product version (e.g. 0.27.0)                 [required]
#   BVAULT_BIN         path to the compiled bvault binary            [required]
#   PKG_ARCH           arch label baked into the file name + the
#                      distribution's hostArchitectures (arm64|x86_64)
#                      [default: host arch]
#   OUTPUT_DIR         where the .pkg is written [default: target/pkg]
#   INSTALLER_IDENTITY "Developer ID Installer: <team>" to sign with;
#                      unset ⇒ unsigned pkg (notarisation happens in CI)
#
# Notarisation + stapling (xcrun notarytool / stapler) is a CI concern and
# is intentionally NOT done here; a locally built pkg is unsigned unless
# INSTALLER_IDENTITY is set.
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

command -v pkgbuild     >/dev/null 2>&1 || die "pkgbuild not found (this target must run on macOS)."
command -v productbuild >/dev/null 2>&1 || die "productbuild not found (this target must run on macOS)."

: "${VERSION:?VERSION must be set}"
: "${BVAULT_BIN:?BVAULT_BIN must be set (path to the compiled bvault binary)}"
[ -f "$BVAULT_BIN" ] || die "BVAULT_BIN does not exist: $BVAULT_BIN"

PKG_ARCH="${PKG_ARCH:-$(uname -m)}"
# `uname -m` reports arm64 on Apple Silicon and x86_64 on Intel — both are
# already the labels we want, so no remapping is needed.
OUTPUT_DIR="${OUTPUT_DIR:-target/pkg}"

# Repo-relative asset locations (this script lives in installers/cli/pkg/).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MANPAGE="$CLI_DIR/manpage/bvault.1"
COMP_BASH="$CLI_DIR/completions/bvault.bash"
COMP_ZSH="$CLI_DIR/completions/_bvault"

[ -f "$MANPAGE" ]   || die "manpage missing: $MANPAGE"
[ -f "$COMP_BASH" ] || die "bash completion missing: $COMP_BASH"
[ -f "$COMP_ZSH" ]  || die "zsh completion missing: $COMP_ZSH"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
ROOT="$WORK/root"

# Lay out the install root exactly as it should appear under /.
install -d -m 0755 "$ROOT/usr/local/bin"
install -d -m 0755 "$ROOT/usr/local/share/man/man1"
install -d -m 0755 "$ROOT/usr/local/etc/bash_completion.d"
install -d -m 0755 "$ROOT/usr/local/share/zsh/site-functions"

install -m 0755 "$BVAULT_BIN" "$ROOT/usr/local/bin/bvault"
gzip -9 -c "$MANPAGE" > "$ROOT/usr/local/share/man/man1/bvault.1.gz"
chmod 0644 "$ROOT/usr/local/share/man/man1/bvault.1.gz"
install -m 0644 "$COMP_BASH" "$ROOT/usr/local/etc/bash_completion.d/bvault"
install -m 0644 "$COMP_ZSH"  "$ROOT/usr/local/share/zsh/site-functions/_bvault"

mkdir -p "$OUTPUT_DIR"

# Best-effort strip of removable xattrs (quarantine, etc.) so they don't
# ride along in the payload. Note: modern macOS attaches a protected
# `com.apple.provenance` xattr to executables that cannot be removed; it
# surfaces as harmless AppleDouble (`._name`) entries in the payload
# listing, which the Installer restores as xattrs (not as literal files)
# on the target. This is expected and does not affect the install.
xattr -rc "$ROOT" 2>/dev/null || true
export COPYFILE_DISABLE=1

# 1) Component package: the raw payload rooted at /.
COMPONENT_PKG="$WORK/component.pkg"
pkgbuild \
    --root "$ROOT" \
    --identifier "com.bastionvault.cli" \
    --version "$VERSION" \
    --install-location "/" \
    "$COMPONENT_PKG"

# 2) Distribution package: wrap the component so it installs via the macOS
#    Installer GUI and via `installer -pkg`, and carries the arch guard.
DIST="$WORK/distribution.xml"
sed -e "s/@VERSION@/$VERSION/g" -e "s/@HOSTARCH@/$PKG_ARCH/g" \
    "$SCRIPT_DIR/distribution.xml" > "$DIST"

OUT_PKG="$OUTPUT_DIR/bvault-$VERSION-darwin-$PKG_ARCH.pkg"

SIGN_ARGS=()
if [ -n "${INSTALLER_IDENTITY:-}" ]; then
    SIGN_ARGS=(--sign "$INSTALLER_IDENTITY")
    echo "==> signing with Developer ID Installer identity"
else
    echo "==> INSTALLER_IDENTITY not set — building an UNSIGNED pkg"
    echo "    (CI signs + notarises; a local unsigned pkg is fine for testing)"
fi

# ${SIGN_ARGS[@]+...} guards the empty-array case for the bash 3.2 that
# ships with macOS, where a bare "${SIGN_ARGS[@]}" under `set -u` is an
# "unbound variable" error.
productbuild \
    --distribution "$DIST" \
    --package-path "$WORK" \
    ${SIGN_ARGS[@]+"${SIGN_ARGS[@]}"} \
    "$OUT_PKG"

echo ""
echo "==> Built $OUT_PKG"
if command -v pkgutil >/dev/null 2>&1; then
    echo "==> payload:"
    pkgutil --payload-files "$OUT_PKG" | sed 's/^/    /'
fi
