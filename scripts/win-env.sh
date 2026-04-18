#!/usr/bin/env bash
# Source this file in Git Bash to prepare the shell for BastionVault Windows builds.
# Usage: source scripts/win-env.sh

add_path() {
    case ":$PATH:" in
        *":$1:"*) ;;
        *) export PATH="$1:$PATH" ;;
    esac
}

# --- Locate Strawberry Perl ---------------------------------------------------
# MSYS2/Git Bash ships its own perl at /usr/bin/perl which is missing modules
# that openssl-src needs (e.g. Locale::Maketext::Simple). We must make sure
# Strawberry Perl wins.
STRAWBERRY_PERL=""
STRAWBERRY_ROOT=""
for candidate in \
    "/c/Strawberry/perl/bin/perl.exe" \
    "/c/strawberry/perl/bin/perl.exe" \
    "$USERPROFILE/scoop/apps/strawberry-perl/current/perl/bin/perl.exe"
do
    if [ -x "$candidate" ]; then
        STRAWBERRY_PERL="$candidate"
        STRAWBERRY_ROOT="$(dirname "$(dirname "$(dirname "$candidate")")")"
        break
    fi
done

if [ -n "$STRAWBERRY_PERL" ]; then
    add_path "$STRAWBERRY_ROOT/perl/bin"
    add_path "$STRAWBERRY_ROOT/perl/site/bin"
    add_path "$STRAWBERRY_ROOT/c/bin"
    # Pin the perl used by the openssl-src build script, bypassing PATH lookup.
    export OPENSSL_SRC_PERL="$STRAWBERRY_PERL"
fi

# --- NASM ---------------------------------------------------------------------
[ -d "/c/Program Files/NASM" ] && add_path "/c/Program Files/NASM"

# --- Node.js ------------------------------------------------------------------
[ -d "/c/Program Files/nodejs" ] && add_path "/c/Program Files/nodejs"

# --- Report -------------------------------------------------------------------
echo "BastionVault Windows env loaded."
echo "  perl: $(command -v perl 2>/dev/null || echo MISSING)"
echo "  nasm: $(command -v nasm 2>/dev/null || echo MISSING)"
echo "  node: $(command -v node 2>/dev/null || echo MISSING)"
if [ -n "${OPENSSL_SRC_PERL:-}" ]; then
    echo "  OPENSSL_SRC_PERL=$OPENSSL_SRC_PERL"
fi
