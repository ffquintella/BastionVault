#!/usr/bin/env bash
# Container smoke test for the client-downloads image.
#
# The Phase 2 acceptance criteria from
# features/packaging-distribution-website.md, executed against a real running
# container: a browseable index, `/manifest.json` echoing the operator's bytes,
# `/vX.Y.Z/<file>` with the right MIME, and a 404 for everything else.
#
# Run it through the make target, which builds the image first:
#
#   make downloads-image-test
#
# Environment:
#   CONTAINER_TOOL   podman | docker (auto-detected)
#   IMAGE            image reference to test (default bastionvault-downloads:latest)
#   PLATFORM         platform to run (default linux/amd64)
#   PORT             host port to publish on (default 18080)

set -euo pipefail

CONTAINER_TOOL="${CONTAINER_TOOL:-$(command -v podman >/dev/null 2>&1 && echo podman || echo docker)}"
IMAGE="${IMAGE:-bastionvault-downloads:latest}"
PLATFORM="${PLATFORM:-linux/amd64}"
PORT="${PORT:-18080}"
NAME="bv-downloads-smoke-$$"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
fixture="$repo_root/cmd/bv-downloads-server/fixtures/v0.4.0"
manifest="$fixture/manifest.json"

fail=0
check() {
    local label="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        printf '  ok   %-52s %s\n' "$label" "$actual"
    else
        printf '  FAIL %-52s expected %s, got %s\n' "$label" "$expected" "$actual"
        fail=1
    fi
}

cleanup() {
    "$CONTAINER_TOOL" rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Starting $IMAGE as $NAME on :$PORT"
"$CONTAINER_TOOL" run -d --name "$NAME" \
    --platform "$PLATFORM" \
    -p "$PORT:8080" \
    -v "$fixture:/srv/bv-downloads:ro" \
    "$IMAGE" --verify-hashes >/dev/null

base="http://127.0.0.1:$PORT"
for _ in $(seq 1 50); do
    if [ "$(curl -sS -o /dev/null -w '%{http_code}' "$base/healthz" 2>/dev/null || true)" = "200" ]; then
        break
    fi
    sleep 0.2
done

echo "==> Container log"
"$CONTAINER_TOOL" logs "$NAME" 2>&1 | sed 's/^/    /'

status()   { curl -sS -o /dev/null -w '%{http_code}' "$base$1"; }
ctype()    { curl -sS -o /dev/null -w '%{content_type}' "$base$1"; }

echo "==> Documented routes"
check "GET /healthz"            "200" "$(status /healthz)"
check "GET / (content-type)"    "text/html; charset=utf-8" "$(ctype /)"
check "GET /manifest.json"      "application/json" "$(ctype /manifest.json)"

curl -sS "$base/manifest.json" > "/tmp/$NAME.manifest.json"
if cmp -s "/tmp/$NAME.manifest.json" "$manifest"; then
    printf '  ok   %-52s %s\n' "manifest.json is byte-identical" "$(wc -c < "$manifest" | tr -d ' ') bytes"
else
    printf '  FAIL %-52s\n' "manifest.json differs from the mounted file"
    fail=1
fi
rm -f "/tmp/$NAME.manifest.json"

echo "==> Every artefact, with the MIME its kind pins"
while IFS='|' read -r name expected; do
    [ -n "$name" ] || continue
    check "GET /v0.4.0/$name" "$expected" "$(ctype "/v0.4.0/$name")"
    if curl -sS "$base/v0.4.0/$name" | cmp -s - "$fixture/v0.4.0/$name"; then
        printf '  ok   %-52s bytes match the mounted file\n' "$name"
    else
        printf '  FAIL %-52s body differs from the mounted file\n' "$name"
        fail=1
    fi
    check "GET /v0.4.0/$name.sig" "application/octet-stream" "$(ctype "/v0.4.0/$name.sig")"
    check "GET /v0.4.0/$name.pem" "application/x-pem-file"   "$(ctype "/v0.4.0/$name.pem")"
done <<EOF
$(python3 - "$manifest" <<'PY'
import json, sys
mime = {
    "deb": "application/vnd.debian.binary-package",
    "rpm": "application/x-rpm",
    "pkg": "application/x-newton-compatible-pkg",
    "msi": "application/x-msi",
}
for f in json.load(open(sys.argv[1]))["files"]:
    print("%s|%s" % (f["name"], mime[f["name"].rsplit(".", 1)[1]]))
PY
)
EOF

echo "==> Everything else is a 404"
for path in /index.html /static/style.css /v0.4.0/ /v0.4.0 /v0.4.0/nope.deb \
            '/../etc/passwd' '/v0.4.0/../../../etc/passwd' '/%2e%2e/etc/passwd'; do
    check "GET $path" "404" "$(status "$path")"
done

echo "==> No write path"
for method in POST PUT DELETE PATCH; do
    check "$method /v0.4.0/bvault_0.4.0_amd64.deb" "404" \
        "$(curl -sS -X "$method" -o /dev/null -w '%{http_code}' "$base/v0.4.0/bvault_0.4.0_amd64.deb")"
done

echo "==> A manifest naming a missing file refuses to start"
broken="$(mktemp -d)"
mkdir -p "$broken/v9.9.9"
cat > "$broken/manifest.json" <<'JSON'
{"version":"9.9.9","released":"2026-06-01","files":[
 {"platform":"linux","arch":"amd64","kind":"cli-deb","name":"bvault_9.9.9_amd64.deb","size":1,
  "sha256":"0000000000000000000000000000000000000000000000000000000000000000"}]}
JSON
if out=$("$CONTAINER_TOOL" run --rm --platform "$PLATFORM" \
        -v "$broken:/srv/bv-downloads:ro" "$IMAGE" 2>&1); then
    printf '  FAIL %-52s started anyway\n' "broken manifest"
    fail=1
else
    case "$out" in
        *bvault_9.9.9_amd64.deb*missing\ from\ disk*)
            printf '  ok   %-52s %s\n' "broken manifest refused" "$out" ;;
        *)
            printf '  FAIL %-52s unexpected error: %s\n' "broken manifest" "$out"
            fail=1 ;;
    esac
fi
rm -rf "$broken"

echo ""
if [ "$fail" -eq 0 ]; then
    echo "==> downloads image smoke: PASS"
else
    echo "==> downloads image smoke: FAIL"
fi
exit "$fail"
