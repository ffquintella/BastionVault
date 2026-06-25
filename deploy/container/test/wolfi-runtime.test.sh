#!/usr/bin/env bash
# Test harness for the Wolfi-based runtime images.
#
# Two layers:
#
#   1. STATIC (always runs, no container tool needed): asserts both
#      Containerfiles pin the Wolfi base for their runtime stage, no
#      longer reference distroless, install the CA bundle, create the
#      nonroot 65532 user, and keep the bvault entrypoint. This catches
#      a regression of the base image in plain CI without a 10-15 min
#      image build.
#
#   2. SMOKE (opt-in via BV_CONTAINER_SMOKE=1, requires podman or
#      docker): actually builds the production image and asserts the
#      running container is Wolfi (`ID=wolfi` in /etc/os-release), runs
#      as UID 65532, ships the CA bundle, and that the bvault binary
#      executes (`bvault --version`). A second build with
#      INCLUDE_SHELL=0 asserts the shell is stripped.
#
# Usage:
#   deploy/container/test/wolfi-runtime.test.sh            # static only
#   BV_CONTAINER_SMOKE=1 deploy/container/test/wolfi-runtime.test.sh
#   BV_CONTAINER_SMOKE=1 CONTAINER_TOOL=docker deploy/container/test/wolfi-runtime.test.sh
#
# Exit non-zero on the first failed assertion. Designed to be invoked
# from `make container-image-test`.

set -euo pipefail

# Resolve repo root from this script's location so it works regardless
# of the caller's CWD.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
PROD_FILE="${REPO_ROOT}/deploy/container/Containerfile"
DEBUG_FILE="${REPO_ROOT}/deploy/container/Containerfile.debug"

WOLFI_REF='cgr.dev/chainguard/wolfi-base'

pass=0
fail=0

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail + 1)); }
note() { printf '\033[1m%s\033[0m\n' "$1"; }

# assert_grep <file> <pattern> <description>
assert_grep() {
    if grep -qE "$2" "$1"; then ok "$3"; else bad "$3 (pattern: $2)"; fi
}

# assert_no_grep <file> <pattern> <description>
assert_no_grep() {
    if grep -qE "$2" "$1"; then bad "$3 (unexpected match: $2)"; else ok "$3"; fi
}

# ─────────────────────────── Static checks ───────────────────────────
note "Static: production Containerfile (${PROD_FILE#"${REPO_ROOT}/"})"
[ -f "$PROD_FILE" ] || { bad "Containerfile missing"; exit 1; }
assert_grep    "$PROD_FILE" "^FROM .*${WOLFI_REF}.* AS runtime"  "runtime stage is FROM wolfi-base"
assert_no_grep "$PROD_FILE" "gcr.io/distroless"                  "no distroless reference remains"
assert_no_grep "$PROD_FILE" "debian:bookworm-slim AS tools"      "no Debian busybox staging stage remains"
assert_grep    "$PROD_FILE" "apk add --no-cache ca-certificates" "installs the CA bundle via apk"
assert_grep    "$PROD_FILE" "^USER 65532:65532"                  "runs as USER 65532:65532 (nonroot from base)"
assert_grep    "$PROD_FILE" 'ENTRYPOINT \["/usr/local/bin/bvault"\]' "entrypoint is bvault"
assert_grep    "$PROD_FILE" "ARG INCLUDE_SHELL"                  "INCLUDE_SHELL build arg preserved"

note "Static: debug Containerfile (${DEBUG_FILE#"${REPO_ROOT}/"})"
[ -f "$DEBUG_FILE" ] || { bad "Containerfile.debug missing"; exit 1; }
assert_grep    "$DEBUG_FILE" "^FROM ${WOLFI_REF}.* AS runtime"   "runtime stage is FROM wolfi-base"
assert_no_grep "$DEBUG_FILE" "gcr.io/distroless"                 "no distroless reference remains"
assert_grep    "$DEBUG_FILE" "apk add --no-cache .*iproute2 tcpdump curl" "installs ss/ip/tcpdump/curl via apk"
assert_grep    "$DEBUG_FILE" "^USER 65532:65532"                 "runs as USER 65532:65532 (nonroot from base)"

if [ "${BV_CONTAINER_SMOKE:-0}" != "1" ]; then
    note "Smoke checks skipped (set BV_CONTAINER_SMOKE=1 to build + run the image)."
    echo ""
    note "Result: ${pass} passed, ${fail} failed"
    [ "$fail" -eq 0 ]
    exit $?
fi

# ─────────────────────────── Smoke checks ────────────────────────────
TOOL="${CONTAINER_TOOL:-$(command -v podman >/dev/null 2>&1 && echo podman || echo docker)}"
command -v "$TOOL" >/dev/null 2>&1 || { bad "container tool '$TOOL' not found"; exit 1; }

# Build natively for the host arch — QEMU cross-builds segfault rustc in
# the builder, and the smoke test only needs one arch to prove the base.
HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    x86_64|amd64)  PLATFORM=linux/amd64 ;;
    arm64|aarch64) PLATFORM=linux/arm64 ;;
    *)             PLATFORM=linux/amd64 ;;
esac

IMG="bastionvault-wolfi-test:smoke"
note "Smoke: building ${IMG} (${PLATFORM}) with ${TOOL} — this can take 10-15 min"
"$TOOL" build --platform "$PLATFORM" \
    -f "$PROD_FILE" -t "$IMG" "$REPO_ROOT"

# run_in_image <description> <expected-substring> <cmd...>
run_in_image() {
    local desc="$1"; local want="$2"; shift 2
    local out
    if out="$("$TOOL" run --rm --entrypoint "$1" "$IMG" "${@:2}" 2>&1)"; then
        if printf '%s' "$out" | grep -qiE "$want"; then ok "$desc"; else
            bad "$desc (got: $(printf '%s' "$out" | head -1))"
        fi
    else
        bad "$desc (command failed: $out)"
    fi
}

note "Smoke: inspecting the running container"
# bvault binary executes and reports a version.
run_in_image "bvault --version runs"            '[0-9]+\.[0-9]+'        /usr/local/bin/bvault --version
# Runtime base is genuinely Wolfi.
run_in_image "runtime base is Wolfi"            'ID=wolfi'             cat /etc/os-release
# CA bundle present for outbound TLS.
run_in_image "CA bundle present"                'certificate|\.pem|\.crt' sh -c 'ls /etc/ssl/certs/ 2>/dev/null || ls /etc/ssl/ 2>/dev/null'
# Container runs as the nonroot 65532 identity.
run_in_image "runs as UID 65532"               '^65532$'              id -u

note "Smoke: INCLUDE_SHELL=0 build is shell-less"
IMG_NOSH="bastionvault-wolfi-test:noshell"
"$TOOL" build --platform "$PLATFORM" --build-arg INCLUDE_SHELL=0 \
    -f "$PROD_FILE" -t "$IMG_NOSH" "$REPO_ROOT"
if "$TOOL" run --rm --entrypoint /bin/sh "$IMG_NOSH" -c 'echo hi' >/dev/null 2>&1; then
    bad "INCLUDE_SHELL=0 still has a /bin/sh"
else
    ok "INCLUDE_SHELL=0 has no /bin/sh"
fi

# Cleanup test images (best effort).
"$TOOL" rmi -f "$IMG" "$IMG_NOSH" >/dev/null 2>&1 || true

echo ""
note "Result: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
