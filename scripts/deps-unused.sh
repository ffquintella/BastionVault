#!/usr/bin/env bash
#
# Report unused direct dependencies in the crates WE own.
#
#   scripts/deps-unused.sh          # report; exit 1 if anything is found
#   scripts/deps-unused.sh --warn   # report; always exit 0 (CI advisory mode)
#
# Wraps `cargo machete`, which walks every Cargo.toml under the working
# directory. That sweep includes trees we do not own and must not fail CI over:
#
#   IronRDP/                        git submodule (Devolutions fork)
#   third_party/hiqlite/            git submodule (our hiqlite fork)
#   plugins-ext/                    git submodule (reference plugins)
#
# So the sweep is filtered down to our own manifests. Findings in the excluded
# trees are still printed, marked as informational, because they are worth
# knowing when re-vendoring or bumping a submodule — they just never fail.
#
# cargo-machete is a STATIC scan for `use` of each dependency. It has two
# systematic blind spots, both of which produced real findings in the Phase 0
# triage and both of which are handled with a
# `[package.metadata.cargo-machete] ignored = [...]` entry plus a reason:
#
#   * package name != lib name (`hcl-rs` exposes `hcl`;
#     `smolder-smb-core` exposes `smolder_core`)
#   * dependencies that are never imported because they exist to PIN A FEATURE
#     for the transitive graph (`tower`'s `util`, `rusb`'s `vendored`,
#     `rustls`'s `aws_lc_rs`). Removing one of these changes feature
#     unification, not just the manifest — so they are kept, not dropped.
#
# Never add to an `ignored` list to quiet the tool. Add only with a reason that
# explains why the scan is wrong.

set -euo pipefail

WARN_ONLY=0
[[ "${1:-}" == "--warn" ]] && WARN_ONLY=1

if ! command -v cargo-machete >/dev/null 2>&1; then
  echo "cargo-machete is not installed. Install it with:" >&2
  echo "    cargo install --locked cargo-machete" >&2
  exit 69
fi

# Manifests we do not own. Matched as substrings against cargo-machete's
# reported path.
EXCLUDED_RE='IronRDP/|third_party/hiqlite/|plugins-ext/'

RAW=$(mktemp); trap 'rm -f "$RAW" "$OURS" "$THEIRS"' EXIT
OURS=$(mktemp)
THEIRS=$(mktemp)

# cargo-machete exits non-zero when it finds anything; that is the signal we
# re-derive ourselves after filtering, so do not let `set -e` abort here.
cargo machete . >"$RAW" 2>&1 || true

# Group the report by manifest, then split ours from theirs. cargo-machete's
# format is a `<crate> -- <path>:` header followed by tab-indented dep names.
python3 - "$RAW" "$OURS" "$THEIRS" "$EXCLUDED_RE" <<'PY'
import re, sys
raw, ours_f, theirs_f, excluded_re = sys.argv[1:5]
excluded = re.compile(excluded_re)

blocks, cur = [], None
for line in open(raw):
    m = re.match(r'^(\S+) -- (\S+):\s*$', line)
    if m:
        cur = {"crate": m.group(1), "path": m.group(2), "deps": []}
        blocks.append(cur)
    elif cur is not None and line.startswith(("\t", "    ")) and line.strip():
        cur["deps"].append(line.strip())
    elif line.strip() == "":
        cur = None

ours, theirs = [], []
for b in blocks:
    if not b["deps"]:
        continue
    (theirs if excluded.search(b["path"]) else ours).append(b)

def dump(path, bs):
    with open(path, "w") as f:
        for b in bs:
            f.write("  %s (%s)\n" % (b["crate"], b["path"]))
            for d in b["deps"]:
                f.write("      %s\n" % d)

dump(ours_f, ours)
dump(theirs_f, theirs)
PY

if [[ -s "$THEIRS" ]]; then
  echo "── vendored / submodule trees (informational, never fails) ──"
  cat "$THEIRS"
  echo
fi

if [[ -s "$OURS" ]]; then
  echo "── unused direct dependencies in OUR crates ──"
  cat "$OURS"
  echo
  echo "For each one, decide which it is:"
  echo "  * genuinely dead        -> delete it from the manifest"
  echo "  * name mismatch, or a   -> add to [package.metadata.cargo-machete]"
  echo "    feature pin              ignored = [...] WITH A REASON"
  echo
  if [[ $WARN_ONLY -eq 1 ]]; then
    echo "(advisory mode: not failing)"
    exit 0
  fi
  exit 1
fi

echo "==> no unused direct dependencies in our crates."
