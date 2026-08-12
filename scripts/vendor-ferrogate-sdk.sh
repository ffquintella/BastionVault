#!/usr/bin/env bash
#
# Re-vendor the FerroGate Rust SDK subset under third_party/ferrogate-sdk-rust/.
#
#   scripts/vendor-ferrogate-sdk.sh              # newest release
#   scripts/vendor-ferrogate-sdk.sh --version 0.21.3
#   scripts/vendor-ferrogate-sdk.sh --check      # report drift, change nothing
#
# This is a DEVELOPER tool, run by hand. It is deliberately NOT part of any
# build: `cargo build` must never reach the network for these crates.
#
# Why not download at build time? Two reasons.
#
#   1. It would not help publishing. `cargo publish` resolves every
#      dependency in its *published* (registry) form from the manifest
#      before it will stage a tarball; a dependency sitting on disk at a
#      `path` does not satisfy it. We proved this in-tree: packaging
#      bv_plugin_manifest failed with "no matching package named
#      bv_plugin_surface found" while that crate was right there on disk.
#      Downloading the SDK changes nothing about that.
#
#   2. These three crates verify FerroGate machine-identity tokens — they
#      are the trust root of the `auth/ferrogate/` backend. Fetching them
#      during a build moves the build's trust base from "source reviewed in
#      a commit" to "whatever that URL served at build time", and makes
#      builds non-reproducible and offline-hostile. PROVENANCE.md chose the
#      vendored model on purpose.
#
# So: this script automates the fetch, the digest check, and the manifest
# de-inheritance, and leaves the result as a reviewable diff. You still
# read the diff and commit it.

set -euo pipefail

REPO="ffquintella/FerroGate"
DEST="third_party/ferrogate-sdk-rust"
# The subset BastionVault actually links. ferro-proto / ferro-svid /
# ferro-attest are deliberately excluded — unused by the verification
# paths, and they drag in protoc / TPM build requirements.
CRATES=(ferro-crypto ferro-child-verify ferro-svid-verify)

VERSION=""
CHECK_ONLY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --check)   CHECK_ONLY=1; shift ;;
    -h|--help) sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

command -v curl >/dev/null || { echo "curl is required" >&2; exit 69; }
command -v shasum >/dev/null || command -v sha256sum >/dev/null \
  || { echo "shasum or sha256sum is required" >&2; exit 69; }

sha256() {
  if command -v shasum >/dev/null; then shasum -a 256 "$1" | cut -d' ' -f1
  else sha256sum "$1" | cut -d' ' -f1; fi
}

current_version() {
  # The vendored version is recorded identically in all three manifests;
  # read it from one rather than trusting the prose in PROVENANCE.md.
  grep -m1 -E '^version' "$DEST/crates/ferro-crypto/Cargo.toml" 2>/dev/null \
    | sed 's/.*"\(.*\)".*/\1/' || echo "none"
}

# ── Resolve the target version ────────────────────────────────────────
if [[ -z "$VERSION" ]]; then
  echo "==> resolving newest release of $REPO ..."
  VERSION=$(curl -sS --max-time 30 -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/releases?per_page=30" \
    | python3 -c "
import json,sys,re
rs = json.load(sys.stdin)
if isinstance(rs, dict):
    sys.exit('GitHub API: %s' % rs.get('message'))
best = None
for r in rs:
    if r.get('prerelease') or r.get('draft'):
        continue
    m = re.search(r'v(\d+)\.(\d+)\.(\d+)\$', r['tag_name'])
    if not m:
        continue
    key = tuple(int(g) for g in m.groups())
    # Only consider releases that actually ship the Rust SDK asset.
    if not any('sdk-rust' in a['name'] for a in r.get('assets', [])):
        continue
    if best is None or key > best[0]:
        best = (key, '.'.join(m.groups()))
if best is None:
    sys.exit('no release found carrying a ferrogate-sdk-rust asset')
print(best[1])
")
fi

CURRENT=$(current_version)
echo "    vendored: $CURRENT"
echo "    target:   $VERSION"

if [[ $CHECK_ONLY -eq 1 ]]; then
  if [[ "$CURRENT" == "$VERSION" ]]; then
    echo "==> up to date."
    exit 0
  fi
  echo "==> DRIFT: vendored $CURRENT, newest is $VERSION."
  echo "    run: make vendor-ferrogate-sdk"
  exit 1
fi

if [[ "$CURRENT" == "$VERSION" ]]; then
  echo "==> already at $VERSION; re-vendoring anyway to confirm the tree matches."
fi

TARBALL="ferrogate-sdk-rust-${VERSION}.tgz"
URL="https://github.com/$REPO/releases/download/releases/v${VERSION}/${TARBALL}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "==> downloading $URL"
if ! curl -sSfL --max-time 120 -o "$WORK/$TARBALL" "$URL"; then
  echo "error: download failed. Check that releases/v$VERSION ships $TARBALL." >&2
  exit 1
fi

DIGEST=$(sha256 "$WORK/$TARBALL")
echo "    sha256: $DIGEST"
echo "    bytes:  $(wc -c < "$WORK/$TARBALL" | tr -d ' ')"

tar xzf "$WORK/$TARBALL" -C "$WORK"
SRC="$WORK/ferrogate-sdk-rust"
[[ -d "$SRC" ]] || { echo "error: unexpected tarball layout (no ferrogate-sdk-rust/)" >&2; exit 1; }

for c in "${CRATES[@]}"; do
  [[ -d "$SRC/crates/$c" ]] || { echo "error: $c missing from the tarball" >&2; exit 1; }
done

# ── Copy the subset, then de-inherit each manifest ─────────────────────
#
# Upstream manifests use `version.workspace = true` and
# `dep = { workspace = true }`. A nested workspace under our excluded
# third_party/ path does not resolve that inheritance, so each crate's
# concrete values are inlined here — copied verbatim from the SDK's
# [workspace.package] / [workspace.dependencies]. `src/` is untouched.
echo "==> vendoring: ${CRATES[*]}"
for c in "${CRATES[@]}"; do
  rm -rf "$DEST/crates/$c"
  mkdir -p "$DEST/crates"
  cp -R "$SRC/crates/$c" "$DEST/crates/$c"
done

VERSION="$VERSION" DEST="$DEST" SRC="$SRC" CRATES="${CRATES[*]}" python3 <<'PY'
import os, tomllib, pathlib

version = os.environ["VERSION"]
dest    = pathlib.Path(os.environ["DEST"])
src     = pathlib.Path(os.environ["SRC"])
crates  = os.environ["CRATES"].split()

ws = tomllib.loads((src / "Cargo.toml").read_text())["workspace"]
ws_pkg  = ws.get("package", {})
ws_deps = ws.get("dependencies", {})


def emit(value):
    """Render a dependency value as inline TOML."""
    if isinstance(value, str):
        return '"%s"' % value
    parts = []
    for k, v in value.items():
        if k == "workspace":
            continue
        if isinstance(v, bool):
            parts.append("%s = %s" % (k, "true" if v else "false"))
        elif isinstance(v, list):
            parts.append("%s = [%s]" % (k, ", ".join('"%s"' % x for x in v)))
        else:
            parts.append('%s = "%s"' % (k, v))
    return "{ %s }" % ", ".join(parts)


def resolve(name, value):
    """Replace `{ workspace = true }` with the workspace's own entry."""
    if isinstance(value, dict) and value.get("workspace"):
        base = ws_deps.get(name)
        if base is None:
            raise SystemExit("%s: no [workspace.dependencies] entry" % name)
        if isinstance(base, str):
            base = {"version": base}
        merged = dict(base)
        # A crate may add `features` / `optional` on top of the workspace entry.
        for k, v in value.items():
            if k == "workspace":
                continue
            if k == "features":
                merged["features"] = sorted(set(base.get("features", [])) | set(v))
            else:
                merged[k] = v
        return merged if len(merged) > 1 else merged.get("version", merged)
    return value


for c in crates:
    path = dest / "crates" / c / "Cargo.toml"
    m = tomllib.loads(path.read_text())
    pkg = m["package"]

    header = (
        "# Vendored from the FerroGate releases/v%s SDK (see ../../PROVENANCE.md).\n"
        "# Manifest de-inherited from the SDK workspace so the crate stands alone as a\n"
        "# path dependency of BastionVault; the `src/` sources are verbatim.\n"
        "#\n"
        "# Regenerate with `make vendor-ferrogate-sdk` — do not hand-edit.\n" % version
    )
    out = [header, "[package]"]

    # Order the package keys deterministically, inlining anything inherited.
    for key in ["name", "description", "version", "edition",
                "rust-version", "license", "repository", "authors"]:
        v = pkg.get(key)
        if isinstance(v, dict) and v.get("workspace"):
            v = ws_pkg.get(key)
        if v is None:
            continue
        if isinstance(v, list):
            out.append('%-12s = [%s]' % (key, ", ".join('"%s"' % x for x in v)))
        else:
            out.append('%-12s = "%s"' % (key, v))

    # `[lints] workspace = true` cannot resolve outside the SDK workspace.
    for section in ["features", "dependencies", "dev-dependencies", "build-dependencies"]:
        if section not in m:
            continue
        out.append("")
        out.append("[%s]" % section)
        if section == "features":
            for k, v in m[section].items():
                out.append('%s = [%s]' % (k, ", ".join('"%s"' % x for x in v)))
        else:
            width = max(len(k) for k in m[section]) if m[section] else 0
            for k, v in m[section].items():
                out.append("%-*s = %s" % (width, k, emit(resolve(k, v))))

    path.write_text("\n".join(out) + "\n")
    print("    de-inherited %s" % path)
PY

# ── Refresh PROVENANCE.md ─────────────────────────────────────────────
python3 - "$VERSION" "$DIGEST" "$TARBALL" "$REPO" "$DEST" <<'PY'
import sys, pathlib, re
version, digest, tarball, repo, dest = sys.argv[1:6]
p = pathlib.Path(dest) / "PROVENANCE.md"
t = p.read_text()
url = "https://github.com/%s/releases/tag/releases/v%s" % (repo, version)
table = (
    "| | |\n|---|---|\n"
    "| Project | FerroGate |\n"
    "| Release | `releases/v%s` |\n"
    "| URL | %s |\n"
    "| Asset | `%s` |\n"
    "| SHA-256 | `%s` |\n"
    "| SDK version | `%s` |\n" % (version, url, tarball, digest, version)
)
t = re.sub(r"\| \| \|\n\|---\|---\|\n(?:\|.*\n)+", table, t, count=1)
t = re.sub(r"releases/v\d+\.\d+\.\d+", "releases/v%s" % version, t)
p.write_text(t)
print("    updated %s" % p)
PY

echo
echo "==> vendored FerroGate SDK $VERSION."
echo "    sha256 $DIGEST"
echo
echo "    NEXT: review the diff, then build and test the ferrogate paths:"
echo "      git diff --stat $DEST"
echo "      cargo check --lib"
echo "      cargo nextest run --lib -E 'test(ferrogate)'"
echo
echo "    These crates verify machine-identity tokens. A version bump is a"
echo "    security-relevant change — read the diff, do not just commit it."
