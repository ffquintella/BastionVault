#!/usr/bin/env bash
#
# Compile the HSM seal backends. Nothing else in this repository does.
#
#   scripts/check-hsm.sh            # the cheap check: bv-core, both backends
#   scripts/check-hsm.sh --deep     # ...plus the image's own build graph
#
# Or via make:
#
#   make check-hsm
#   make check-hsm DEEP=1
#
# ── Why this exists ───────────────────────────────────────────────
#
# `hsm_mock` and `hsm_yubihsm2` are off in every default build, and AGENTS.md §5
# bans `--all-features` (it turns on the vendored-libusb C build, storage_mysql,
# every cloud target and every PQC preview at once, materialising a second
# feature-variant of a 1200-crate graph). So all four of these stayed green
# while the backends did not compile:
#
#   cargo check --workspace --all-targets   the CI gate — default features
#   make check-isolated                     `-p X` per member — default features
#   make test / test-changed                default features
#   the unit + integration matrices         default features
#
# The FIRST build that compiled them was the official container image
# (deploy/container/Containerfile bakes in BVAULT_FEATURES), ~6 minutes into a
# cross-compile, twice. Most recently: Phase 4.5 moved `src/hsm/` into
# `crates/bv-core` and left `x509-cert` behind in the root manifest, so
# `hsm/yubihsm2.rs` named a crate its own package did not depend on.
#
# ── What each half covers ─────────────────────────────────────────
#
# 1. THE FEATURE CHAIN, from cargo metadata. Compiles nothing.
#
#    Every `#[cfg(feature = "hsm_*")]` site in the workspace is in `bv-core`
#    (re-derive with: grep -rn 'feature *= *"hsm_' --include='*.rs' src/ crates/).
#    The crates above it own no gated code — only the pass-through feature
#    declarations that carry the flag down:
#
#        bvault-cli/hsm_mock -> bastion_vault/hsm_mock -> bv-core/hsm_mock
#
#    A broken link there is invisible to step 2, and its failure mode is the
#    quiet one: `--features hsm_yubihsm2` on the image build would resolve, do
#    nothing, and ship a binary with no HSM backend in it. `cargo tree` cannot
#    see this — it only prints features that gate a dependency, and `hsm_mock`
#    gates none — so the chain is walked from the manifests instead.
#
# 2. THE COMPILE: `cargo check -p bv-core --features <both>`.
#
#    Because step 1 establishes that bv-core owns all the gated code, this one
#    crate is the whole compile-error surface, and it is the cheap end of the
#    graph: bv-core plus Tier 0/1 beneath it, ~35 s cold on a warm target dir.
#    `-p bvault-cli` would additionally rebuild the 66k-line root crate,
#    bv-server and the CLI to check the same ten cfg blocks.
#
# `--deep` adds that `-p bvault-cli` build anyway. It is what the image
# actually compiles, so it is the honest answer to "would the image build?" —
# it is just far too expensive to be the per-pull-request gate.
#
# The feature list is READ FROM THE CONTAINERFILE, not restated here. A second
# hand-maintained copy is exactly the drift this repository has already paid for
# three times over (see the header of scripts/ci-plan.sh).

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

DEEP=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --deep) DEEP=1; shift ;;
    -h|--help) sed -n '2,60p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "check-hsm: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

CONTAINERFILE=deploy/container/Containerfile

# The image's entry point into the graph. The features come from the
# Containerfile; the package does not, because the `cargo build` line there also
# carries the target triple, the cross-toolchain exports and `--bin`, and
# grepping a package name out of it would be a more fragile coupling than
# naming it. Keep this in step with the `-p` on that line.
ENTRY_PKG=bvault-cli

FEATURES=$(sed -n 's/^ARG BVAULT_FEATURES="\([^"]*\)".*/\1/p' "$CONTAINERFILE" | head -1)
if [[ -z "$FEATURES" ]]; then
  echo "check-hsm: no 'ARG BVAULT_FEATURES=\"...\"' found in $CONTAINERFILE." >&2
  echo "check-hsm: the image stopped declaring its features that way, or moved." >&2
  exit 1
fi

echo "==> features, as the container image declares them: $FEATURES"
echo ""

# ── 1. The feature chain ──────────────────────────────────────────
echo "==> feature chain: $ENTRY_PKG -> ... -> bv-core (cargo metadata; compiles nothing)"

CHECK_HSM_FEATURES="$FEATURES" CHECK_HSM_ENTRY="$ENTRY_PKG" python3 - <<'PY'
import json, os, subprocess, sys

entry = os.environ["CHECK_HSM_ENTRY"]
features = [f.strip() for f in os.environ["CHECK_HSM_FEATURES"].split(",") if f.strip()]

md = json.loads(subprocess.run(
    ["cargo", "metadata", "--format-version", "1", "--no-deps"],
    capture_output=True, text=True, check=True).stdout)
pkgs = {p["name"]: p for p in md["packages"]}

def dep_names(pkg):
    """Manifest key -> real package name, so a renamed dependency still resolves."""
    return {(d["rename"] or d["name"]): d["name"] for d in pkgs[pkg]["dependencies"]}

def reaches(pkg, feat, seen):
    """Can (pkg, feat) turn on the same feature in bv-core?

    Walks the `[features]` tables only. `dep:foo` entries are ignored: they add
    an optional dependency, they do not forward a feature.
    """
    if (pkg, feat) in seen:
        return False
    seen.add((pkg, feat))
    if pkg == "bv-core":
        return feat in pkgs[pkg]["features"]
    if pkg not in pkgs or feat not in pkgs[pkg]["features"]:
        return False
    renames = dep_names(pkg)
    for entry in pkgs[pkg]["features"][feat]:
        if entry.startswith("dep:"):
            continue
        if "/" in entry:
            dep, sub = entry.split("/", 1)
            dep = dep.rstrip("?")                 # `dep?/feat` is weak, still forwards
            if reaches(renames.get(dep, dep), sub, seen):
                return True
        elif reaches(pkg, entry, seen):           # a local feature enabling another
            return True
    return False

bad = []
for f in features:
    if f not in pkgs.get(entry, {}).get("features", {}):
        bad.append(f"{entry} declares no feature '{f}'")
    elif not reaches(entry, f, set()):
        bad.append(f"{entry}/{f} does not reach bv-core/{f} — the flag would resolve and do nothing")
    else:
        print(f"    ok  {entry}/{f} -> bv-core/{f}")

if bad:
    print("", file=sys.stderr)
    for b in bad:
        print(f"    FAIL  {b}", file=sys.stderr)
    print("", file=sys.stderr)
    print("check-hsm: the container image would build a binary without the backend it asked for.", file=sys.stderr)
    sys.exit(1)
PY

echo ""

# ── 2. The compile ────────────────────────────────────────────────
echo "==> cargo check -p bv-core --features $FEATURES"
cargo check -p bv-core --features "$FEATURES"

if [[ "$DEEP" == "1" ]]; then
  echo ""
  echo "==> cargo check -p $ENTRY_PKG --features $FEATURES   (the image's own graph)"
  cargo check -p "$ENTRY_PKG" --features "$FEATURES"
fi

echo ""
echo "==> check-hsm: the seal backends compile."
