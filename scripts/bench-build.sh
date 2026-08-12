#!/usr/bin/env bash
#
# Measure what a small change costs in this workspace, reproducibly.
#
#   scripts/bench-build.sh              # measure, print, append to the log
#   scripts/bench-build.sh --no-log     # measure and print only
#   scripts/bench-build.sh --with-target-size   # also `du -sh target/` (slow)
#   scripts/bench-build.sh --repeat 5   # more samples per scenario (default 3)
#
# This is the instrument for `roadmaps/workspace-decomposition.md`. Every phase
# of the decomposition reports its delta against the log this writes, so the
# scenarios below must stay stable and comparable across phases.
#
# WHAT IS MEASURED, and why these and not others:
#
#   check-noop        `cargo check --lib` with nothing touched. The floor —
#                     cargo's own fingerprint-scan cost. Should stay ~1s; if it
#                     grows, the workspace has too many units, not too few.
#   check-leaf        ...after touching one leaf engine file. What a developer
#                     editing one secret engine pays. THE number the split
#                     should move.
#   check-core        ...after touching src/core.rs. Worst case: the god object
#                     every module depends on. Phase 2 (breaking the
#                     Core <-> modules cycle) is what should move this.
#   test-build-leaf   `nextest --no-run` after touching one leaf file — i.e.
#                     compile + LINK the test binary. Much larger than
#                     check-leaf because linking a ~245 MB rlib dominates, and
#                     linking is exactly what `cargo check` never does.
#
# `cargo check` is cheap and already well tuned here; the codegen+link numbers
# are the ones that hurt, so both are recorded rather than just the fast one.
#
# DELIBERATELY NOT SET: RUSTC_BOOTSTRAP / `-Z threads`. The Makefile's
# FAST_BUILD_TARGETS enable rustc's parallel front-end for interactive dev, but
# a benchmark needs one documented configuration, not a nightly escape hatch
# whose thread count varies by host. Numbers here are therefore *slower* than a
# `make build` on the same machine, and comparable to each other. The log records
# whether the env var leaked in anyway.
#
# A warm target/ is assumed and required: this measures INCREMENTAL cost, not a
# cold build. A cold build of this tree (1200+ crates, aws-lc-rs, wasmtime,
# Tauri) is a CI concern tracked separately via `cargo build --timings`.
#
# STATE SENSITIVITY — run this from a settled target/, i.e. right after a normal
# `make build` / `make test`, and NOT right after building other package or
# feature subsets (`cargo check -p <other>`, `--workspace`, `--all-features`).
# Those leave extra build configurations in the cache, which changes both the
# fingerprint-scan cost and how much rustc's incremental cache can reuse. Doing
# it wrong inflated every column by ~60% in one measured run — see the second row
# of docs/build-timings/baseline.md, kept as a worked example.

set -euo pipefail

LOG="docs/build-timings/baseline.md"
DO_LOG=1
WITH_TARGET_SIZE=0
# 3 is the smallest n that yields a usable median. Raise it when a phase claims a
# win close to the noise floor.
REPEAT="${REPEAT:-3}"

# The file touched to simulate "a developer edited one leaf engine". Chosen
# because transit is the most isolated module in the tree (19 files, exactly one
# reference to `Core`, 0 of the last 300 commits) — so it measures the *floor*
# of a per-engine edit, not an unusually entangled case.
#
# When Phase 3 moves transit into its own crate this path changes; override it
# and record the change in the log's Notes column so rows stay comparable.
LEAF_FILE="${LEAF_FILE:-src/modules/transit/mod.rs}"
CORE_FILE="${CORE_FILE:-src/core.rs}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-log)           DO_LOG=0; shift ;;
    --repeat)           REPEAT="$2"; shift 2 ;;
    --with-target-size) WITH_TARGET_SIZE=1; shift ;;
    --leaf)             LEAF_FILE="$2"; shift 2 ;;
    -h|--help)          sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

for f in "$LEAF_FILE" "$CORE_FILE"; do
  [[ -f "$f" ]] || { echo "error: $f not found (pass --leaf to override)" >&2; exit 1; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Sub-second timing, portably. `date +%s` is 1s-granular (useless for the ~1s
# no-op case) and `date +%N` is absent on macOS.
elapsed() {
  local log="$1"; shift
  python3 -c "
import subprocess, sys, time
log = open(sys.argv[1], 'w')
t = time.monotonic()
r = subprocess.run(sys.argv[2:], stdout=log, stderr=subprocess.STDOUT)
print('%.2f' % (time.monotonic() - t))
sys.exit(r.returncode)
" "$log" "$@"
}

echo "==> warming up (this measures INCREMENTAL cost, so the tree must be built)"
if ! elapsed "$WORK/warmup.log" cargo check --lib >/dev/null; then
  echo "error: warm-up 'cargo check --lib' failed:" >&2
  tail -30 "$WORK/warmup.log" >&2
  exit 1
fi
# The test profile is a separate fingerprint set from `check`; warm it too, or
# test-build-leaf would absorb a first-ever codegen of the whole crate.
echo "    warming the test profile (first run compiles the lib for codegen)"
elapsed "$WORK/warmup2.log" cargo nextest run --lib --no-run >/dev/null || {
  echo "error: warm-up test build failed:" >&2; tail -30 "$WORK/warmup2.log" >&2; exit 1; }

# Run a scenario REPEAT times and report the MEDIAN.
#
# Repetition is not optional rigour here: measured run-to-run spread on this tree
# is +/-20-25% for the `check-*` scenarios (rustc's incremental cache is warmer or
# colder depending on what ran just before). A single sample cannot distinguish a
# real improvement from noise, and the whole point of this log is to attribute
# improvements to phases. Median, not mean, so one scheduler hiccup cannot drag
# the row.
#
# Progress goes to stderr so the caller's $(...) captures only the number and the
# user still sees each row appear live.
measure() {  # measure <label> <touch-file|-> <cmd...>
  local label="$1" touch_file="$2"; shift 2
  local samples=()
  for _ in $(seq "$REPEAT"); do
    [[ "$touch_file" != "-" ]] && touch "$touch_file"
    local secs
    secs=$(elapsed "$WORK/$label.log" "$@") || {
      echo "error: '$label' failed:" >&2; tail -30 "$WORK/$label.log" >&2; exit 1; }
    samples+=("$secs")
  done
  local median
  median=$(printf '%s\n' "${samples[@]}" | python3 -c "
import sys, statistics
xs = [float(l) for l in sys.stdin if l.strip()]
print('%.2f' % statistics.median(xs))
")
  if [[ ${#samples[@]} -gt 1 ]]; then
    printf '  %-18s %8ss   (n=%d: %s)\n' "$label" "$median" "${#samples[@]}" "${samples[*]}" >&2
  else
    printf '  %-18s %8ss\n' "$label" "$median" >&2
  fi
  echo "$median"
}

echo "==> measuring (median of $REPEAT run(s) per scenario)"
# Order matters: no-op first (nothing invalidated), then progressively wider
# invalidations.
#
# NOTE, as of the pre-decomposition baseline: check-leaf and check-core are
# expected to be EQUAL, because `src/modules/transit/mod.rs` and `src/core.rs`
# live in the same crate, so touching either invalidates the same compilation
# unit. That equality is the problem this roadmap exists to fix — today the build
# system cannot tell a self-contained 3,155-line engine apart from the 1,699-line
# object every module depends on. The two rows should DIVERGE once Phase 2 and
# Phase 3 land; until then, treat any gap between them as noise.
CHECK_NOOP=$(measure check-noop      -           cargo check --lib)
CHECK_LEAF=$(measure check-leaf      "$LEAF_FILE" cargo check --lib)
CHECK_CORE=$(measure check-core      "$CORE_FILE" cargo check --lib)
TEST_LEAF=$(measure test-build-leaf  "$LEAF_FILE" cargo nextest run --lib --no-run)

# ── Static size facts ─────────────────────────────────────────────────
# Newest matching rlib. BSD and GNU find disagree on -newermt, so sort by mtime
# with ls instead of filtering in find.
RLIB=$(ls -t target/debug/deps/libbastion_vault-*.rlib 2>/dev/null | head -1 || true)
if [[ -n "${RLIB:-}" && -f "$RLIB" ]]; then
  RLIB_MB=$(( $(wc -c < "$RLIB") / 1024 / 1024 ))
else
  RLIB_MB="n/a"
fi
LOCK_PKGS=$(grep -c '^\[\[package\]\]' Cargo.lock 2>/dev/null || echo "n/a")
SRC_FILES=$(find src -name '*.rs' | wc -l | tr -d ' ')
SRC_LINES=$(find src -name '*.rs' -exec cat {} + | wc -l | tr -d ' ')
WS_MEMBERS=$(cargo metadata --no-deps --format-version 1 \
  | python3 -c "import json,sys; print(len(json.load(sys.stdin)['packages']))")
TARGET_SIZE="(not measured)"
[[ $WITH_TARGET_SIZE -eq 1 ]] && TARGET_SIZE=$(du -sh target 2>/dev/null | cut -f1)

COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DIRTY=""
git diff-index --quiet HEAD -- 2>/dev/null || DIRTY=" (dirty)"
STAMP=$(date -u '+%Y-%m-%d %H:%M UTC')
CORES=$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "?")
RUSTC=$(rustc --version | awk '{print $2}')
BOOTSTRAP="${RUSTC_BOOTSTRAP:-unset}"

echo
echo "════ build cost @ $COMMIT$DIRTY ════"
printf '  %-22s %s\n' \
  "check-noop"        "${CHECK_NOOP}s" \
  "check-leaf"        "${CHECK_LEAF}s" \
  "check-core"        "${CHECK_CORE}s" \
  "test-build-leaf"   "${TEST_LEAF}s" \
  "lib rlib (debug)"  "${RLIB_MB} MB" \
  "lock packages"     "$LOCK_PKGS" \
  "workspace members" "$WS_MEMBERS" \
  "src/"              "$SRC_LINES lines / $SRC_FILES files" \
  "target/"           "$TARGET_SIZE"
echo "  leaf file: $LEAF_FILE"
echo "  host: ${CORES} cores, rustc $RUSTC, RUSTC_BOOTSTRAP=$BOOTSTRAP"

if [[ $DO_LOG -eq 1 ]]; then
  mkdir -p "$(dirname "$LOG")"
  if [[ ! -f "$LOG" ]]; then
    cat > "$LOG" <<'HEADER'
# Build-cost baseline

Appended by `make bench-build` (`scripts/bench-build.sh`). One row per run.
Every phase of [the decomposition](../../roadmaps/workspace-decomposition.md)
reports its delta against this table.

Read the script's header comment for what each column means and why it was
chosen. In short: `check-*` is front-end only, `test-build-leaf` includes the
link that `cargo check` never does, and none of these use the Makefile's
`-Z threads` escape hatch, so they are slower than `make build` and comparable
to each other.

Numbers are INCREMENTAL on a warm `target/`. A cold-build picture is a separate
artefact — see the `--timings` HTML in this directory.

| date | commit | noop | leaf | core | test+link | rlib | lock | members | src lines | cores | notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
HEADER
  fi
  printf '| %s | `%s`%s | %ss | %ss | %ss | %ss | %s MB | %s | %s | %s | %s | |\n' \
    "$STAMP" "$COMMIT" "$DIRTY" "$CHECK_NOOP" "$CHECK_LEAF" "$CHECK_CORE" \
    "$TEST_LEAF" "$RLIB_MB" "$LOCK_PKGS" "$WS_MEMBERS" "$SRC_LINES" "$CORES" >> "$LOG"
  echo
  echo "==> appended a row to $LOG"
fi
