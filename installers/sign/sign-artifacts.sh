#!/usr/bin/env bash
#
# Unified, key-agnostic signing for BastionVault installer artifacts.
#
# Signs every installer it finds under the given directories (default: target/)
# with the right mechanism for each type, using WHATEVER keys the operator
# supplies via the environment. Every mechanism is INDEPENDENT and OPTIONAL:
# supply a key and that type gets signed; omit it and that type is skipped
# with a note. This is "sign with any key" — nothing here is tied to a
# specific HSM, identity, or cert.
#
# Additionally, every artifact gets a cross-platform Cosign signature (any
# cosign key, or keyless) and a line in SHA256SUMS.
#
# ── Keys / config (all optional) ──────────────────────────────────────────
#   .deb / .rpm  (GPG)
#     BV_GPG_KEY        key id / email / fingerprint to sign with
#     BV_GPG_HOMEDIR    GNUPGHOME override (optional)
#
#   .msi / .exe  (Authenticode via osslsigncode — runs on macOS/Linux)
#     BV_WIN_PFX        path to a PKCS#12 (.pfx/.p12) code-signing cert
#     BV_WIN_PFX_PASS   its password (optional)
#     -- or a PEM pair --
#     BV_WIN_CERT       PEM certificate     BV_WIN_KEY   PEM private key
#     BV_WIN_TS_URL     RFC3161 timestamp URL [http://timestamp.digicert.com]
#     BV_WIN_NO_TS=1    disable timestamping (offline)
#
#   .pkg  (macOS Developer ID + optional notarization)
#     BV_MACOS_INSTALLER_IDENTITY  "Developer ID Installer: <team>"
#     BV_NOTARY_PROFILE            notarytool keychain profile (optional)
#
#   .nupkg  (native NuGet signature — optional)
#     BV_NUGET_CERT_FP  code-signing cert SHA-1 fingerprint (uses `nuget sign`)
#     BV_NUGET_TS_URL   timestamp URL
#
#   Cosign  (cross-platform, applied to EVERY artifact)
#     BV_COSIGN_KEY     path to a cosign private key (+ COSIGN_PASSWORD)
#     BV_COSIGN_KEYLESS=1   use keyless (OIDC) signing instead of a key
#
# Usage: sign-artifacts.sh [dir ...]      # defaults to scanning target/
set -euo pipefail

ok()   { echo "  [signed]  $*"; }
skip() { echo "  [skip]    $*"; }
info() { echo "==> $*"; }
warn() { echo "  [warn]    $*" >&2; }

DIRS=("$@")
[ ${#DIRS[@]} -eq 0 ] && DIRS=("target")

[ -n "${BV_GPG_HOMEDIR:-}" ] && export GNUPGHOME="$BV_GPG_HOMEDIR"

# Collect artifacts across the requested directories.
artifacts=()
while IFS= read -r -d '' f; do artifacts+=("$f"); done < <(
    find "${DIRS[@]}" -type f \
        \( -name '*.deb' -o -name '*.rpm' -o -name '*.msi' -o -name '*.exe' \
           -o -name '*.nupkg' -o -name '*.pkg' \) -print0 2>/dev/null | sort -z
)

if [ ${#artifacts[@]} -eq 0 ]; then
    echo "No artifacts (.deb/.rpm/.msi/.exe/.nupkg/.pkg) found under: ${DIRS[*]}"
    exit 0
fi

info "found ${#artifacts[@]} artifact(s) to sign"

# ── .deb / .rpm : GPG ──────────────────────────────────────────────────────
sign_deb() {
    local f="$1"
    if [ -z "${BV_GPG_KEY:-}" ]; then skip "$f (no BV_GPG_KEY)"; return; fi
    if command -v dpkg-sig >/dev/null 2>&1; then
        dpkg-sig --sign builder -k "$BV_GPG_KEY" "$f" >/dev/null || return 1
        ok "$f (embedded dpkg-sig)"
    else
        gpg ${BV_GPG_KEY:+--local-user "$BV_GPG_KEY"} --armor --yes --detach-sign \
            --output "$f.asc" "$f" || return 1
        ok "$f -> $f.asc (detached GPG; dpkg-sig not installed)"
    fi
}
sign_rpm() {
    local f="$1"
    if [ -z "${BV_GPG_KEY:-}" ]; then skip "$f (no BV_GPG_KEY)"; return; fi
    if command -v rpmsign >/dev/null 2>&1; then
        rpmsign --define "_gpg_name $BV_GPG_KEY" --addsign "$f" >/dev/null || return 1
        ok "$f (embedded rpm --addsign)"
    else
        gpg --local-user "$BV_GPG_KEY" --armor --yes --detach-sign \
            --output "$f.asc" "$f" || return 1
        ok "$f -> $f.asc (detached GPG; rpmsign not installed)"
    fi
}

# ── .msi / .exe : Authenticode via osslsigncode ────────────────────────────
sign_authenticode() {
    local f="$1"
    if ! command -v osslsigncode >/dev/null 2>&1; then
        skip "$f (osslsigncode not installed)"; return
    fi
    local -a key_args
    if [ -n "${BV_WIN_PFX:-}" ]; then
        key_args=(-pkcs12 "$BV_WIN_PFX")
        [ -n "${BV_WIN_PFX_PASS:-}" ] && key_args+=(-pass "$BV_WIN_PFX_PASS")
    elif [ -n "${BV_WIN_CERT:-}" ] && [ -n "${BV_WIN_KEY:-}" ]; then
        key_args=(-certs "$BV_WIN_CERT" -key "$BV_WIN_KEY")
    else
        skip "$f (no BV_WIN_PFX or BV_WIN_CERT/BV_WIN_KEY)"; return
    fi
    local -a ts_args=()
    if [ "${BV_WIN_NO_TS:-0}" != "1" ]; then
        ts_args=(-ts "${BV_WIN_TS_URL:-http://timestamp.digicert.com}")
    fi
    # ${arr[@]+...} guards empty arrays under bash 3.2 (macOS) + set -u.
    osslsigncode sign "${key_args[@]}" -h sha256 \
        -n "BastionVault" -i "https://github.com/ffquintella/BastionVault" \
        ${ts_args[@]+"${ts_args[@]}"} -in "$f" -out "$f.signed" >/dev/null || return 1
    mv -f "$f.signed" "$f" || return 1
    ok "$f (Authenticode)"
}

# ── .pkg : macOS Developer ID + optional notarization ──────────────────────
sign_pkg() {
    local f="$1"
    if [ -z "${BV_MACOS_INSTALLER_IDENTITY:-}" ]; then
        skip "$f (no BV_MACOS_INSTALLER_IDENTITY)"; return
    fi
    if ! command -v productsign >/dev/null 2>&1; then
        skip "$f (productsign not available — macOS only)"; return
    fi
    productsign --sign "$BV_MACOS_INSTALLER_IDENTITY" "$f" "$f.signed" >/dev/null || return 1
    mv -f "$f.signed" "$f" || return 1
    ok "$f (Developer ID Installer)"
    if [ -n "${BV_NOTARY_PROFILE:-}" ]; then
        info "notarizing $f (profile $BV_NOTARY_PROFILE)"
        xcrun notarytool submit "$f" --keychain-profile "$BV_NOTARY_PROFILE" --wait || return 1
        xcrun stapler staple "$f" || return 1
        ok "$f (notarized + stapled)"
    fi
}

# ── .nupkg : native NuGet signature (optional) ─────────────────────────────
sign_nupkg() {
    local f="$1"
    if [ -z "${BV_NUGET_CERT_FP:-}" ]; then skip "$f (no BV_NUGET_CERT_FP; Cosign still applies)"; return; fi
    if ! command -v nuget >/dev/null 2>&1; then skip "$f (nuget not installed)"; return; fi
    nuget sign "$f" -CertificateFingerprint "$BV_NUGET_CERT_FP" \
        ${BV_NUGET_TS_URL:+-Timestamper "$BV_NUGET_TS_URL"} -Overwrite || return 1
    ok "$f (NuGet signature)"
}

# ── Cosign : cross-platform, every artifact ────────────────────────────────
# Optional cross-check layer — always NON-FATAL (returns 0) so a cosign
# version quirk never blocks the primary platform-native signatures.
#
# cosign v3 replaced the detached .sig/.pem outputs with a single .cosign.bundle
# (Sigstore bundle: signature + cert). We emit the bundle on v3+ and fall back
# to .sig/.pem on v2. Verify with:
#   v3: cosign verify-blob --key <pub> --new-bundle-format --bundle f.cosign.bundle f
#   v2: cosign verify-blob --key <pub> --signature f.sig [--certificate f.pem] f
cosign_major=""
if command -v cosign >/dev/null 2>&1; then
    cosign_major=$(cosign version 2>/dev/null | sed -n 's/.*GitVersion:[[:space:]]*v\([0-9]*\).*/\1/p' | head -1)
fi
cosign_blob() {
    local f="$1"
    command -v cosign >/dev/null 2>&1 || { skip "$f (cosign not installed)"; return 0; }
    local -a mode
    if [ -n "${BV_COSIGN_KEY:-}" ]; then
        mode=(--key "$BV_COSIGN_KEY")
    elif [ "${BV_COSIGN_KEYLESS:-0}" = "1" ]; then
        mode=()   # keyless (OIDC + Rekor)
    else
        skip "$f (no BV_COSIGN_KEY and BV_COSIGN_KEYLESS!=1)"; return 0
    fi
    if [ "${cosign_major:-0}" -ge 3 ] 2>/dev/null; then
        if cosign sign-blob --yes ${mode[@]+"${mode[@]}"} --new-bundle-format \
               --bundle "$f.cosign.bundle" "$f" >/dev/null 2>&1; then
            ok "$f -> $f.cosign.bundle (cosign)"
        else
            warn "$f (cosign bundle signing failed — non-fatal)"
        fi
    else
        local -a out=(--output-signature "$f.sig")
        [ "${BV_COSIGN_KEYLESS:-0}" = "1" ] && out+=(--output-certificate "$f.pem")
        if cosign sign-blob --yes ${mode[@]+"${mode[@]}"} "${out[@]}" "$f" >/dev/null 2>&1; then
            ok "$f -> $f.sig (cosign)"
        else
            warn "$f (cosign signing failed — non-fatal)"
        fi
    fi
    return 0
}

# Native signing failures are collected and re-raised at the end (a signing
# step must fail loud), but one failure doesn't stop the rest of the run.
failures=()
for f in "${artifacts[@]}"; do
    info "signing $(basename "$f")"
    case "$f" in
        *.deb)       sign_deb "$f"          || failures+=("$f") ;;
        *.rpm)       sign_rpm "$f"          || failures+=("$f") ;;
        *.msi|*.exe) sign_authenticode "$f" || failures+=("$f") ;;
        *.pkg)       sign_pkg "$f"          || failures+=("$f") ;;
        *.nupkg)     sign_nupkg "$f"        || failures+=("$f") ;;
    esac
    cosign_blob "$f"   # non-fatal
done

# ── SHA256SUMS over every artifact ─────────────────────────────────────────
info "writing SHA256SUMS"
SUMS="${BV_SUMS_FILE:-SHA256SUMS}"
: > "$SUMS"
sumtool() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
for f in "${artifacts[@]}"; do sumtool "$f" >> "$SUMS"; done
echo "  wrote $SUMS ($(wc -l < "$SUMS" | tr -d ' ') entries)"

if [ ${#failures[@]} -ne 0 ]; then
    echo ""
    warn "native signing FAILED for ${#failures[@]} artifact(s):"
    for f in "${failures[@]}"; do warn "  $f"; done
    exit 1
fi
info "signing pass complete"
