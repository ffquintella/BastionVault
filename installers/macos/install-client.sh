#!/usr/bin/env bash
#
# Install already-built BastionVault macOS client packages onto THIS Mac.
#
# This is the local-workstation counterpart to `make gui-macos-pkg` /
# `make macos-cli-pkg`: those produce the `.pkg` files, this one hands them
# to Apple's `installer(8)` so the GUI lands in /Applications and the CLI
# lands under /usr/local. Invoked by `make macos-client-install`.
#
# Both installs need root (they write outside $HOME), so this script calls
# `sudo` — once up front, so you are prompted a single time rather than
# per package.
#
# Configuration comes from the environment:
#
#   GUI_PKG           path to BastionVault-<version>-<arch>.pkg   [optional]
#   CLI_PKG           path to bvault-<version>-darwin-<arch>.pkg  [optional]
#                     (at least one of the two must be given)
#   INSTALL_TARGET    installer(8) target volume [default: /]
#   BV_QUIT_RUNNING   1 ⇒ gracefully quit a running BastionVault.app before
#                     replacing it. Unset ⇒ refuse to install over a running
#                     app, so an unsealed vault is never yanked out from
#                     under you.
set -euo pipefail

die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || die "install-client.sh must run on macOS (installer(8) is an Apple tool)."
command -v installer >/dev/null 2>&1 || die "installer(8) not found."

GUI_PKG="${GUI_PKG:-}"
CLI_PKG="${CLI_PKG:-}"
INSTALL_TARGET="${INSTALL_TARGET:-/}"

[ -n "$GUI_PKG" ] || [ -n "$CLI_PKG" ] || die "set GUI_PKG and/or CLI_PKG to the .pkg(s) to install."
[ -z "$GUI_PKG" ] || [ -f "$GUI_PKG" ] || die "GUI_PKG does not exist: $GUI_PKG (build it with 'make gui-macos-pkg')"
[ -z "$CLI_PKG" ] || [ -f "$CLI_PKG" ] || die "CLI_PKG does not exist: $CLI_PKG (build it with 'make macos-cli-pkg')"

# ── Don't replace a running app underneath its own process ─────────────
#
# Overwriting the bundle of a running app leaves it half-old/half-new: the
# already-mapped executable keeps running while its resources are swapped
# out. Worse, for BastionVault the running GUI may hold an unsealed
# embedded vault. Refuse by default; BV_QUIT_RUNNING=1 opts into a
# graceful AppleScript quit (which lets the app seal + flush on its way
# out) rather than a kill.
if [ -n "$GUI_PKG" ] && pgrep -f 'BastionVault\.app/Contents/MacOS/' >/dev/null 2>&1; then
    if [ "${BV_QUIT_RUNNING:-}" = "1" ]; then
        echo "==> BastionVault.app is running — asking it to quit"
        osascript -e 'quit app "BastionVault"' >/dev/null 2>&1 || true
        for _ in $(seq 1 20); do
            pgrep -f 'BastionVault\.app/Contents/MacOS/' >/dev/null 2>&1 || break
            sleep 0.5
        done
        if pgrep -f 'BastionVault\.app/Contents/MacOS/' >/dev/null 2>&1; then
            die "BastionVault.app did not quit within 10s — quit it manually and re-run."
        fi
    else
        die "BastionVault.app is running. Quit it first (it may hold an unsealed vault),
       or re-run with BV_QUIT_RUNNING=1 to have this script ask it to quit:
           make macos-client-install BV_QUIT_RUNNING=1"
    fi
fi

# ── One sudo prompt for the whole run ─────────────────────────────────
if [ "$(id -u)" != "0" ]; then
    echo "==> installing to $INSTALL_TARGET requires administrator rights"
    sudo -v || die "could not obtain administrator rights."
    SUDO=(sudo)
else
    SUDO=()
fi

install_pkg() {
    local pkg="$1" what="$2"
    echo ""
    echo "==> installing the $what: $(basename "$pkg")"
    ${SUDO[@]+"${SUDO[@]}"} installer -pkg "$pkg" -target "$INSTALL_TARGET" \
        || die "installer(8) failed for $pkg"
}

# GUI first, CLI second — so the last thing printed is the CLI check,
# which is what you immediately go and type.
[ -z "$GUI_PKG" ] || install_pkg "$GUI_PKG" "GUI (BastionVault.app → /Applications)"
[ -z "$CLI_PKG" ] || install_pkg "$CLI_PKG" "CLI (bvault → /usr/local/bin)"

# ── Verify what actually landed ────────────────────────────────────────
echo ""
echo "==> installed:"

if [ -n "$GUI_PKG" ]; then
    APP="${INSTALL_TARGET%/}/Applications/BastionVault.app"
    [ -d "$APP" ] || die "install reported success but $APP is missing."
    APP_VER="$(defaults read "$APP/Contents/Info.plist" CFBundleShortVersionString 2>/dev/null || echo '?')"
    echo "    $APP (v$APP_VER)"
fi

if [ -n "$CLI_PKG" ]; then
    BIN="${INSTALL_TARGET%/}/usr/local/bin/bvault"
    [ -x "$BIN" ] || die "install reported success but $BIN is missing or not executable."
    echo "    $BIN ($("$BIN" --version 2>/dev/null || echo 'version check failed'))"
    case ":$PATH:" in
        *:/usr/local/bin:*) ;;
        *) echo ""
           echo "    NOTE: /usr/local/bin is not on your PATH. Add it:"
           echo "        echo 'export PATH=\"/usr/local/bin:\$PATH\"' >> ~/.zshrc" ;;
    esac
fi

echo ""
echo "==> done. Launch the GUI with:  open -a BastionVault"
