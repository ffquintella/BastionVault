#!/usr/bin/env bash
# Sign BastionVault executables with a certificate stored on THIS machine.
# Usage and design: installers/sign/README-exe.md
set -euo pipefail

# Paths only; never keys, never passphrases. Outside the repository.
CONF="${BV_SIGN_CONFIG:-${XDG_CONFIG_HOME:-$HOME/.config}/bastionvault/signing.conf}"

say()  { echo "==> $*" >&2; }
ok()   { echo "  [signed] $*" >&2; }
skip() { echo "  [skip]   $*" >&2; }
warn() { echo "  [warn]   $*" >&2; }
die()  { echo "ERROR: $*" >&2; exit 1; }

TMP=""; KC=""
cleanup() {
    [ -n "$KC" ] && security delete-keychain "$KC" >/dev/null 2>&1 || true
    [ -n "$TMP" ] && [ -d "$TMP" ] && rm -rf "$TMP"
    return 0
}
trap cleanup EXIT
mktmp() { [ -n "$TMP" ] || { TMP="$(mktemp -d)"; chmod 700 "$TMP"; }; }

have_tty() { { : </dev/tty; } 2>/dev/null; }
ask() {
    local p="$1" d="${2:-}" a
    if [ -n "$d" ]; then printf '%s [%s]: ' "$p" "$d" >/dev/tty; else printf '%s: ' "$p" >/dev/tty; fi
    IFS= read -r a </dev/tty || a=""
    echo "${a:-$d}"
}
ask_secret() {
    local a
    printf '%s: ' "$1" >/dev/tty
    IFS= read -rs a </dev/tty || a=""
    echo >/dev/tty
    echo "$a"
}

# The config is parsed, never sourced: a config file must not execute code.
cfg_get() { [ -f "$CONF" ] || return 0; sed -n "s/^$1=//p" "$CONF" | tail -1; }
expand() { case "$1" in "~"/*) echo "$HOME/${1#\~/}" ;; *) echo "$1" ;; esac; }

# First OpenSSL that can do ML-DSA; otherwise whatever is on PATH.
OSSL=""; OSSL_PQC=0
find_openssl() {
    [ -n "$OSSL" ] && return 0
    local c cands=() cfg
    cfg="$(cfg_get OPENSSL)"
    [ -n "${BV_SIGN_OPENSSL:-}" ] && cands+=("$BV_SIGN_OPENSSL")
    [ -n "$cfg" ] && cands+=("$(expand "$cfg")")
    cands+=(openssl)
    for c in 3.6 3.5 4 3; do
        cands+=("/opt/homebrew/opt/openssl@$c/bin/openssl" "/usr/local/opt/openssl@$c/bin/openssl")
    done
    for c in "${cands[@]}"; do
        command -v "$c" >/dev/null 2>&1 || continue
        if "$c" list -public-key-algorithms 2>/dev/null | grep -qi 'ML-DSA'; then
            OSSL="$(command -v "$c")"; OSSL_PQC=1; return 0
        fi
    done
    command -v openssl >/dev/null 2>&1 || die "openssl not found"
    OSSL="$(command -v openssl)"
}

cert_algo() {
    "$OSSL" x509 -in "$1" -noout -text 2>/dev/null | sed -n 's/^ *Public Key Algorithm: *//p' | head -1
}
algo_kind() {
    case "$(echo "$1" | tr '[:upper:]' '[:lower:]')" in
        ""|*composite*)                      echo unknown ;;
        *ml-kem*|*mlkem*)                    echo kem ;;
        *ml-dsa*|*mldsa*|*slh-dsa*|*slhdsa*) echo pq ;;
        *)                                   echo classical ;;
    esac
}
key_encrypted() { grep -q 'ENCRYPTED' "$1" 2>/dev/null; }

reject_kem() {
    cat >&2 <<EOF
ERROR: $1 is an ML-KEM certificate (algorithm: $2).
       ML-KEM is a key-encapsulation scheme: its key can encrypt, it cannot sign.
       Nothing here (CMS, Authenticode, codesign) can sign with it.
       Use the ML-DSA (FIPS 204) or SLH-DSA (FIPS 205) certificate instead.
EOF
}

# Echoes the kind (classical|pq); returns 1 with a message when unusable.
validate_pair() {
    local cert="$1" key="$2" algo kind
    [ -f "$cert" ] || { echo "not found: $cert" >&2; return 1; }
    case "$cert" in *.pfx|*.p12) echo classical; return 0 ;; esac
    [ -f "$key" ] || { echo "not found: $key" >&2; return 1; }
    algo="$(cert_algo "$cert")"; kind="$(algo_kind "$algo")"
    case "$kind" in
        kem)     reject_kem "$cert" "$algo"; return 1 ;;
        unknown) echo "no usable public key in $cert (composite/unparsable certs are not supported)" >&2; return 1 ;;
        pq)      [ "$OSSL_PQC" = 1 ] || { echo "$cert is $algo but no OpenSSL >= 3.5 was found (brew install openssl@3.5)" >&2; return 1; } ;;
    esac
    echo "$kind"
}

write_conf() {
    umask 077
    mkdir -p "$(dirname "$CONF")"; chmod 700 "$(dirname "$CONF")" 2>/dev/null || true
    {
        echo "# BastionVault code-signing config. Paths only. Local to this machine; do not commit."
        echo "ENABLED=$1"
        echo "CLASSICAL_CERT=$2"; echo "CLASSICAL_KEY=$3"; echo "CLASSICAL_CHAIN=$4"
        echo "PQC_CERT=$5";       echo "PQC_KEY=$6";       echo "PQC_CHAIN=$7"
        echo "TIMESTAMP_URL=$8"
        echo "OPENSSL=$9"
    } > "$CONF"
    chmod 600 "$CONF"
}

IDC=""; IDK=""; IDH=""
ask_identity() {
    local label="$1" want="$2" c k kind a b
    IDC=""; IDK=""; IDH=""
    while :; do
        c="$(ask "$label certificate file (blank = none)" "")"
        [ -z "$c" ] && return 0
        c="$(expand "$c")"; k=""
        case "$c" in *.pfx|*.p12) ;; *) k="$(expand "$(ask "  private key file" "")")" ;; esac
        if kind="$(validate_pair "$c" "$k")"; then
            if [ "$kind" != "$want" ]; then
                warn "that is a $kind certificate; the $label slot expects $want."; continue
            fi
            if [ -n "$k" ] && ! key_encrypted "$k"; then
                a="$("$OSSL" x509 -in "$c" -noout -pubkey 2>/dev/null || true)"
                b="$("$OSSL" pkey -in "$k" -pubout 2>/dev/null || true)"
                if [ -n "$a" ] && [ -n "$b" ] && [ "$a" != "$b" ]; then
                    warn "the key does not match the certificate."; continue
                fi
            fi
            IDH="$(ask "  intermediate/CA chain PEM (blank = none)" "")"
            [ -n "$IDH" ] && IDH="$(expand "$IDH")"
            IDC="$c"; IDK="$k"; return 0
        fi
        warn "rejected; try again (blank to skip)."
    done
}

do_setup() {
    have_tty || die "setup needs a terminal. Create $CONF by hand (see installers/sign/README-exe.md)."
    find_openssl
    say "code-signing setup; answers are saved to $CONF (paths only)"
    echo "  OpenSSL: $OSSL ($([ "$OSSL_PQC" = 1 ] && echo 'ML-DSA capable' || echo 'no ML-DSA'))" >&2
    echo "  Classical = RSA/ECDSA/Ed25519 (.pem or .pfx/.p12). PQC = ML-DSA/SLH-DSA PEM." >&2
    echo "  An ML-KEM certificate cannot sign and is refused." >&2
    ask_identity "Classical" classical; local cc="$IDC" ck="$IDK" ch="$IDH"
    ask_identity "PQC (ML-DSA)" pq;     local pc="$IDC" pk="$IDK" ph="$IDH"
    if [ -z "$cc$pc" ]; then
        write_conf 0 "" "" "" "" "" "" "" ""
        say "no identity given: signing is DISABLED (saved). Re-run with REDO=1 to change."
        return 0
    fi
    local ts; ts="$(ask "RFC 3161 timestamp URL (blank = none)" "http://timestamp.digicert.com")"
    write_conf 1 "$cc" "$ck" "$ch" "$pc" "$pk" "$ph" "$ts" "$OSSL"
    say "saved $CONF (mode 600)"
}

enabled() { [ -f "$CONF" ] && [ "$(cfg_get ENABLED)" = 1 ]; }

# Exports BV_SIGN_TMP_PASS when the key is encrypted; used via -passin env:.
prep_pass() {
    unset BV_SIGN_TMP_PASS || true
    if [ -n "$1" ] && key_encrypted "$1"; then
        local v="${!2:-}"
        if [ -z "$v" ]; then
            have_tty || die "$1 is encrypted: set $2 or run on a terminal"
            v="$(ask_secret "passphrase for $(basename "$1")")"
        fi
        export BV_SIGN_TMP_PASS="$v"
    fi
}
passin() { if [ -n "${BV_SIGN_TMP_PASS:-}" ]; then echo "-passin env:BV_SIGN_TMP_PASS"; fi; }

UC=""; UK=""
unpack_pfx() {
    mktmp
    local pw="${!2:-}"
    if [ -z "$pw" ] && have_tty; then pw="$(ask_secret "password for $(basename "$1") (blank if none)")"; fi
    UC="$TMP/pfx-cert.pem"; UK="$TMP/pfx-key.pem"
    export BV_SIGN_TMP_PFX="$pw"
    "$OSSL" pkcs12 -in "$1" -passin env:BV_SIGN_TMP_PFX -nokeys -clcerts -out "$UC" 2>/dev/null \
        || "$OSSL" pkcs12 -legacy -in "$1" -passin env:BV_SIGN_TMP_PFX -nokeys -clcerts -out "$UC" \
        || die "cannot open $1 (wrong password?)"
    "$OSSL" pkcs12 -in "$1" -passin env:BV_SIGN_TMP_PFX -nocerts -nodes -out "$UK" 2>/dev/null \
        || "$OSSL" pkcs12 -legacy -in "$1" -passin env:BV_SIGN_TMP_PFX -nocerts -nodes -out "$UK"
    chmod 600 "$UK"; unset BV_SIGN_TMP_PFX
}

cms_detached() {
    local f="$1" out="$2" cert="$3" key="$4" chain="$5" md="${6:-}"
    local -a a=(cms -sign -binary -in "$f" -signer "$cert" -inkey "$key" -outform DER -out "$out")
    [ -n "$chain" ] && a+=(-certfile "$chain")
    [ -n "$md" ] && a+=(-md "$md")
    # shellcheck disable=SC2046
    "$OSSL" "${a[@]}" $(passin)
}
cms_verify() {
    "$OSSL" cms -verify -binary -inform DER -in "$2" -content "$1" -CAfile "$3" \
        -purpose any -partial_chain -out /dev/null 2>/dev/null
}

# codesign needs an identity in a keychain: use a throwaway one.
# The system LibreSSL writes a PKCS#12 that `security import` accepts;
# OpenSSL 3's default AES-256 container is rejected by some macOS releases.
codesign_embedded() {
    local target="$1" cert="$2" key="$3" chain="$4" ts="$5"
    command -v codesign >/dev/null 2>&1 || return 2
    mktmp
    local pw pk12 mk fp tsarg
    pw="$(LC_ALL=C tr -dc 'a-f0-9' </dev/urandom | head -c 32)"
    KC="$TMP/sign.keychain-db"
    pk12="$TMP/id.p12"; mk=/usr/bin/openssl; [ -x "$mk" ] || mk="$OSSL"
    local -a x=(pkcs12 -export -inkey "$key" -in "$cert" -out "$pk12" -passout "pass:$pw")
    [ -n "$chain" ] && x+=(-certfile "$chain")
    # shellcheck disable=SC2046
    "$mk" "${x[@]}" $(passin) || return 1
    security create-keychain -p "$pw" "$KC" >/dev/null
    security set-keychain-settings "$KC"
    security unlock-keychain -p "$pw" "$KC"
    security import "$pk12" -k "$KC" -P "$pw" -T /usr/bin/codesign >/dev/null
    security set-key-partition-list -S apple-tool:,apple: -s -k "$pw" "$KC" >/dev/null 2>&1 || true
    fp="$("$OSSL" x509 -in "$cert" -noout -fingerprint -sha1 | sed 's/.*=//; s/://g')"
    tsarg="--timestamp=none"; [ -n "$ts" ] && tsarg="--timestamp"
    codesign --force --keychain "$KC" --sign "$fp" "$tsarg" "$target" >&2
}

pe_embedded() {
    local f="$1" cert="$2" key="$3" chain="$4" ts="$5"
    command -v osslsigncode >/dev/null 2>&1 || { warn "osslsigncode not installed; $f gets a detached signature instead (brew install osslsigncode)"; return 2; }
    local -a a=(sign -certs "$cert" -key "$key" -h sha256 -n BastionVault)
    [ -n "$chain" ] && a+=(-ac "$chain")
    [ -n "$ts" ] && a+=(-ts "$ts")
    [ -n "${BV_SIGN_TMP_PASS:-}" ] && a+=(-pass "$BV_SIGN_TMP_PASS")
    osslsigncode "${a[@]}" -in "$f" -out "$f.signed" >&2 && mv -f "$f.signed" "$f"
}

ftype() {
    local d; d="$(file -b "$1" 2>/dev/null || true)"
    case "$d" in *Mach-O*) echo macho ;; *PE32*|*MS\ Windows*) echo pe ;; *) echo other ;; esac
}
make_manifest() { ( cd "$1" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 ) > "$2"; }

do_sign() {
    local auto=0 out="" src=""
    while [ $# -gt 0 ]; do
        case "$1" in --auto) auto=1 ;; --out) out="$2"; shift ;; *) src="$1" ;; esac
        shift
    done
    [ -n "$src" ] || die "usage: sign [--auto] [--out DIR] <file|.app>"
    [ -e "$src" ] || die "not found: $src"
    out="${out:-target/signed}"
    local name; name="$(basename "$src")"
    mkdir -p "$out"
    rm -rf "${out:?}/$name" "$out/$name.p7s" "$out/$name.pqc.p7s" "$out/$name.manifest" "$out/$name.sha256"
    cp -R "$src" "$out/$name"
    local dst="$out/$name"

    if [ "${SIGN:-1}" = 0 ]; then skip "$name (SIGN=0)"; return 0; fi
    if [ ! -f "$CONF" ]; then
        if [ "$auto" = 1 ] && ! have_tty; then skip "$name (no signing config at $CONF)"; return 0; fi
        do_setup
    fi
    if ! enabled; then skip "$name (signing disabled in $CONF)"; return 0; fi

    find_openssl
    local ts signed=0
    ts="$(cfg_get TIMESTAMP_URL)"; [ "${BV_SIGN_NO_TS:-0}" = 1 ] && ts=""

    local cc ck ch
    cc="$(expand "$(cfg_get CLASSICAL_CERT)")"; ck="$(expand "$(cfg_get CLASSICAL_KEY)")"; ch="$(expand "$(cfg_get CLASSICAL_CHAIN)")"
    if [ -n "$cc" ]; then
        local C="$cc" K="$ck" t embedded=0 rc=0
        case "$cc" in
            *.pfx|*.p12) unpack_pfx "$cc" BV_SIGN_CLASSICAL_PASS; C="$UC"; K="$UK"; unset BV_SIGN_TMP_PASS || true ;;
            *) prep_pass "$K" BV_SIGN_CLASSICAL_PASS ;;
        esac
        [ "$(algo_kind "$(cert_algo "$C")")" = classical ] || die "$cc is no longer a classical certificate"
        if [ -n "$ch" ] && [ ! -f "$ch" ]; then die "chain file missing: $ch"; fi
        if [ -d "$dst" ]; then t=macho; else t="$(ftype "$dst")"; fi
        if [ "$t" = macho ] && [ "$(uname -s)" = Darwin ]; then
            codesign_embedded "$dst" "$C" "$K" "$ch" "$ts" || die "codesign failed for $name"
            ok "$name (codesign, embedded)"; embedded=1
        elif [ "$t" = pe ]; then
            pe_embedded "$dst" "$C" "$K" "$ch" "$ts" && embedded=1 || rc=$?
            if [ "$embedded" = 1 ]; then ok "$name (Authenticode, embedded)"
            elif [ "$rc" != 2 ]; then die "Authenticode signing failed for $name"; fi
        fi
        if [ "$embedded" = 0 ]; then
            if [ -d "$dst" ]; then
                warn "$name: a classical signature on a bundle needs macOS codesign; none applied"
            else
                cms_detached "$dst" "$out/$name.p7s" "$C" "$K" "$ch" sha256 \
                    || { rm -f "$out/$name.p7s"; die "CMS signing failed for $name"; }
                ok "$name -> $name.p7s (classical, detached CMS)"; embedded=1
            fi
        fi
        [ "$embedded" = 1 ] && signed=1
        unset BV_SIGN_TMP_PASS || true
    fi

    local pc pk ph
    pc="$(expand "$(cfg_get PQC_CERT)")"; pk="$(expand "$(cfg_get PQC_KEY)")"; ph="$(expand "$(cfg_get PQC_CHAIN)")"
    if [ -n "$pc" ]; then
        local kind algo subj="$dst"
        algo="$(cert_algo "$pc")"; kind="$(algo_kind "$algo")"
        if [ "$kind" = kem ]; then reject_kem "$pc" "$algo"; exit 1; fi
        [ "$kind" = pq ] || die "$pc is not a PQC signature certificate (algorithm: ${algo:-unknown})"
        [ "$OSSL_PQC" = 1 ] || die "ML-DSA signing needs OpenSSL >= 3.5 (brew install openssl@3.5)"
        prep_pass "$pk" BV_SIGN_PQC_PASS
        if [ -d "$dst" ]; then make_manifest "$dst" "$out/$name.manifest"; subj="$out/$name.manifest"; fi
        # ML-DSA has no default CMS digest in OpenSSL 3.5; RFC 9882 uses SHA-512.
        cms_detached "$subj" "$out/$name.pqc.p7s" "$pc" "$pk" "$ph" sha512 \
            || { rm -f "$out/$name.pqc.p7s"; die "$algo signing failed for $name"; }
        ok "$name -> $name.pqc.p7s ($algo, detached CMS)"; signed=1
        unset BV_SIGN_TMP_PASS || true
    fi
    [ "$signed" = 1 ] || skip "$name (no identity applied)"
    if [ -f "$dst" ]; then
        ( cd "$out" && { shasum -a 256 "$name" 2>/dev/null || sha256sum "$name"; } > "$name.sha256" )
    fi
    return 0
}

do_verify() {
    local f="${1:?usage: verify <file>}" bad=0 n=0 cc pc ch ph a subj
    [ -e "$f" ] || die "not found: $f"
    find_openssl
    cc="$(expand "$(cfg_get CLASSICAL_CERT)")"; pc="$(expand "$(cfg_get PQC_CERT)")"
    ch="$(expand "$(cfg_get CLASSICAL_CHAIN)")"; ph="$(expand "$(cfg_get PQC_CHAIN)")"
    if [ -d "$f" ] || [ "$(ftype "$f")" = macho ]; then
        if command -v codesign >/dev/null 2>&1 && codesign --verify --strict "$f" 2>/dev/null; then
            echo "  [ok] $f: embedded codesign signature valid"; n=$((n+1))
        fi
    fi
    if [ "$(ftype "$f")" = pe ] && command -v osslsigncode >/dev/null 2>&1 && [ -n "$cc" ]; then
        a="${ch:-$cc}"
        if osslsigncode verify -CAfile "$a" -in "$f" >/dev/null 2>&1; then echo "  [ok] $f: Authenticode valid"; n=$((n+1)); else echo "  [FAIL] $f: Authenticode" >&2; bad=1; fi
    fi
    if [ -f "$f.p7s" ] && [ -n "$cc" ]; then
        case "$cc" in
            *.pfx|*.p12) warn "$f.p7s: verification needs a PEM cert (a pfx is configured)" ;;
            *) a="${ch:-$cc}"
               if cms_verify "$f" "$f.p7s" "$a"; then echo "  [ok] $f.p7s: classical CMS valid"; n=$((n+1)); else echo "  [FAIL] $f.p7s" >&2; bad=1; fi ;;
        esac
    fi
    if [ -f "$f.pqc.p7s" ] && [ -n "$pc" ]; then
        subj="$f"
        if [ -d "$f" ]; then
            subj="$f.manifest"; mktmp; make_manifest "$f" "$TMP/m"
            cmp -s "$TMP/m" "$subj" || { echo "  [FAIL] $f: manifest does not match the bundle" >&2; bad=1; }
        fi
        a="${ph:-$pc}"
        if cms_verify "$subj" "$f.pqc.p7s" "$a"; then echo "  [ok] $f.pqc.p7s: $(cert_algo "$pc") CMS valid"; n=$((n+1)); else echo "  [FAIL] $f.pqc.p7s" >&2; bad=1; fi
    fi
    if [ "$n" = 0 ] && [ "$bad" = 0 ]; then echo "  no signature found for $f" >&2; bad=1; fi
    return "$bad"
}

do_show() {
    [ -f "$CONF" ] || { echo "no configuration at $CONF"; return 0; }
    echo "$CONF"; cat "$CONF"
}

cmd="${1:-}"; if [ $# -gt 0 ]; then shift; fi
case "$cmd" in
    setup)
        if [ -f "$CONF" ] && [ "${1:-}" != "--redo" ]; then say "already configured ($CONF); pass --redo to change"; do_show
        else find_openssl; do_setup; fi ;;
    sign)   do_sign "$@" ;;
    verify) do_verify "$@" ;;
    show)   do_show ;;
    *) echo "usage: sign-exe.sh setup|sign|verify|show (see installers/sign/README-exe.md)" >&2; exit 2 ;;
esac
