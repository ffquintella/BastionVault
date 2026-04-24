#!/usr/bin/env bash
# Keep only the N most-recent rustc incremental sessions per crate.
#
# Each `target/*/incremental/<crate>/` directory contains one
# subdirectory per compiler session (`s-<timestamp>-<hash>/`). rustc
# retains old sessions until its own rotation runs, and on a long-
# running dev loop that accumulates into gigabytes before any GC
# happens. This script trims each crate's session list to the N most
# recent by modification time, deleting the rest. Preserves crate-
# level cache state — only stale generations go.
#
# Defaults keep 3 sessions per crate. Override with:
#
#   KEEP=5 scripts/prune-incremental.sh
#
# Runs as a prerequisite of every compiling Make target via the
# Makefile's `prune-stale` rule, so normal `make build` /
# `make run-dev-gui` invocations self-clean without the operator
# thinking about it.

set -eu

KEEP="${KEEP:-3}"

ROOTS="
  target/debug/incremental
  target/release/incremental
  gui/src-tauri/target/debug/incremental
  gui/src-tauri/target/release/incremental
"

removed_dirs=0

for root in $ROOTS; do
  [ -d "$root" ] || continue

  # Iterate per-crate directory. The glob expands inside the `for`
  # so a missing-match leaves the literal pattern, which we skip
  # via the -d test. Avoids a hard dependency on shopt / nullglob.
  for crate_dir in "$root"/*/; do
    [ -d "$crate_dir" ] || continue

    # `ls -t` sorts newest-first by mtime. Portable across GNU,
    # BSD (macOS), and Git-Bash on Windows. Session directory
    # names are `s-<hex>-<hex>` — no whitespace, so word-splitting
    # is safe here.
    # shellcheck disable=SC2012
    sessions=$(ls -1t -d "$crate_dir"s-*/ 2>/dev/null || true)
    [ -n "$sessions" ] || continue

    count=0
    for _ in $sessions; do
      count=$((count + 1))
    done
    [ "$count" -gt "$KEEP" ] || continue

    # Skip the first KEEP entries (newest), delete the rest.
    idx=0
    for session in $sessions; do
      idx=$((idx + 1))
      if [ "$idx" -le "$KEEP" ]; then
        continue
      fi
      rm -rf "$session"
      removed_dirs=$((removed_dirs + 1))
    done
  done
done

if [ "$removed_dirs" -gt 0 ]; then
  echo "prune-incremental: removed $removed_dirs stale session(s) (kept $KEEP per crate)"
fi
