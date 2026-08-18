#!/usr/bin/env bash
#
# Turn the cargo dependency graph into a GitHub Actions job plan.
#
#   scripts/ci-plan.sh                       # plan for the working tree, to stdout
#   scripts/ci-plan.sh --base origin/main    # plan for a PR against main
#   scripts/ci-plan.sh --full                # the everything plan (what main runs)
#   scripts/ci-plan.sh --pkg bv-engine-pki   # "what would CI do if I touched X?"
#
# Writes `key=value` lines to $GITHUB_OUTPUT when that is set, and a
# human-readable summary to $GITHUB_STEP_SUMMARY. With neither set it prints
# both to stdout, which is how you inspect a plan locally:
#
#   make ci-plan BASE=main
#
# ── Why this is a script and not a `dorny/paths-filter` block ──────
#
# Phase 5 of roadmaps/workspace-decomposition.md sketched path-filtered jobs.
# Path globs are a SECOND copy of the dependency graph, maintained by hand, and
# this repository has already measured its own graph wrong three times with
# three different broken regexes — each time changing the plan (see the
# roadmap's "the third measurement error"). A glob list drifts silently the
# first time a crate gains a dependency, and the failure mode is a green PR
# that skipped the suite that would have caught the bug.
#
# So the affected set comes from `cargo metadata` via scripts/test-changed.sh,
# which is the same code path `make test-changed` uses locally. There is one
# graph, and CI and the inner loop read it the same way.
#
# ── What the plan decides ─────────────────────────────────────────
#
#   unit           one matrix job per affected package (`nextest run -p X --lib`
#                  + `cargo test --doc -p X`), OR one collapsed `--workspace`
#                  job when the affected set is most of the workspace
#   integration    the tests/ binaries, sharded — re-enabled by Phase 5, having
#                  been skipped in CI since the suite existed
#   hiqlite        the port-bound storage/HA suites, when bv-storage is affected
#   cucumber       the harness = false suite, when the root crate is affected
#   isolation      `cargo check -p X` over every member, when any manifest moved
#   hsm            `make check-hsm`, when bv-core, a manifest or the image recipe
#                  moved — the seal backends are off in every other job
#   gui            tsc + vitest, when gui/ (not gui/src-tauri) moved
#
# The `check` gate job in tests.yml is unconditional and is not planned here.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

# ── Tunables, with the measurement behind each ────────────────────
#
# MATRIX_CAP: above this many affected packages, run one `--workspace` job
# instead of N per-package jobs. The reverse-dependency closure sizes on this
# tree fall into two clean groups and nothing lands between them:
#
#     0-1   the Tier 4 leaves — bvault-cli, bv-plugin-pack, bastion-plugin-sdk
#     4-10  every engine, auth backend, bv-core, bv-kernel, bv-server, the root
#     26-33 bv-kernel-api, bv-errors, bv-logical, bv-storage and the rest of
#           Tier 0/1 — i.e. "the substrate changed"
#
# Any cap between 11 and 25 partitions those identically. 12 is far enough from
# both edges to survive a few more crates being added at either end.
#
# Re-derive the groups with (counts lib-bearing packages, so a bin-only crate
# like bv-plugin-pack reads 0):
#     for p in $(cargo metadata --format-version 1 --no-deps \
#                | jq -r '.packages[].name'); do
#       printf '%3d  %s\n' \
#         "$(scripts/test-changed.sh --json --pkg "$p" | jq '.lib_pkgs|length')" "$p"
#     done | sort -n
MATRIX_CAP=${MATRIX_CAP:-12}

# INTEG_SHARD_SIZE: integration binaries per shard. Each tests/ binary is a full
# link of the graph beneath it and was measured at ~190 MB on this tree, so the
# constraint is runner disk (~14 GB free on ubuntu-latest) as much as time.
# 8 binaries is ~1.5 GB of linked output per shard, which leaves room for the
# ~4 GB of cached dependency artefacts and the source tree.
INTEG_SHARD_SIZE=${INTEG_SHARD_SIZE:-8}

BASE=""
FORCE_FULL=0
SEED_PKGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)  BASE="${2:?--base needs a git ref}"; shift 2 ;;
    --full)  FORCE_FULL=1; shift ;;
    --pkg)   SEED_PKGS+=("${2:?--pkg needs a package name}"); shift 2 ;;
    -h|--help) sed -n '2,42p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ci-plan: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

TC_ARGS=(--json)
[[ -n "$BASE" ]] && TC_ARGS+=(--base "$BASE")
for p in ${SEED_PKGS[@]+"${SEED_PKGS[@]}"}; do TC_ARGS+=(--pkg "$p"); done

# Via the environment, not stdin: the plan script is a heredoc on stdin here.
CI_PLAN_INPUT=$(scripts/test-changed.sh "${TC_ARGS[@]}")
export CI_PLAN_INPUT

python3 - "$FORCE_FULL" "$MATRIX_CAP" "$INTEG_SHARD_SIZE" <<'PY'
import json, math, os, sys

force_full, cap, shard_size = (int(a) for a in sys.argv[1:4])
plan = json.loads(os.environ["CI_PLAN_INPUT"])

# A full run is the safe answer, and three separate things ask for one:
#
#   --full          the caller knows (a push to main, or workflow_dispatch);
#                   this is also what keeps main's cache complete for PRs
#   plan["full"]    Cargo.lock / the root manifest / the toolchain / the nextest
#                   config moved, so what the whole workspace compiles against
#                   may have changed
#   ci_files        the workflow itself moved — you cannot validate a CI edit
#                   with an empty matrix, and a PR that reports "nothing to run"
#                   for a change to tests.yml is worse than useless
full = bool(force_full) or plan["full"] or bool(plan["ci_files"])

lib_pkgs = plan["lib_pkgs"]
needs_bin = set(plan["needs_bvault_bin"])
# Packages with a [[bin]] that actually contains tests. Every other bin in this
# workspace would link a full harness to run zero tests, so `--bins` is only
# worth paying for these — same rule, and the same derivation, as
# scripts/test-changed.sh.
bin_pkgs = set(plan["bin_pkgs"])

# Above the cap the matrix has stopped being an optimisation: N jobs each
# rebuild the same substrate from the same cache, and one `--workspace` run
# shares that work instead of paying for it N times.
collapse = full or len(lib_pkgs) > cap

unit_matrix = [] if collapse else [
    # `bvault_bin` is per-package rather than unconditional because linking the
    # ~200 MB bvault binary in a bv-shamir job would cost more than the job.
    {"pkg": p, "bvault_bin": p in needs_bin, "bins": p in bin_pkgs}
    for p in lib_pkgs
]

# `full` means every harness in the workspace, which is not the same as every
# harness an affected package owns — a tests/ binary in a crate nothing depends
# on is still covered. Both lists come from the plan; neither is re-derived
# here, so the "two suites nextest cannot enumerate" exclusion has one home.
integ_bins = plan["all_integration_bins"] if full else plan["integration_bins"]

n_shards = max(1, math.ceil(len(integ_bins) / shard_size)) if integ_bins else 0
integ_matrix = [
    {
        "shard": f"{i + 1}/{n_shards}",
        # One `--test` flag per binary. Sharding by binary and not by
        # `nextest --partition` is deliberate: partitioning splits test
        # EXECUTION but still builds and links every harness in every shard,
        # which is the cost that made this suite unaffordable in CI.
        "tests": " ".join(f"--test {b}" for b in integ_bins[i::n_shards]),
    }
    for i in range(n_shards)
]

run_gui = full or bool(plan["gui_files"])
# bv-storage only. The HA fault-injection binary lives in tests/ and is
# therefore owned by the root crate, which nearly every change reaches — gating
# on that would run a cluster suite on every PR. Both suites exercise
# bv-storage's hiqlite backend, so bv-storage is the trigger that means
# something, and `full` covers the rest on main.
run_hiqlite = full or "bv-storage" in lib_pkgs
run_cucumber = full or "bastion_vault" in lib_pkgs
# Feature unification is per-build, so a manifest edit anywhere can change what
# a DOWNSTREAM crate compiles against without the workspace build noticing.
# That is the Phase 4.5 `log/std` bug exactly: `cargo check --workspace` stayed
# green while `cargo check -p bv-server` was broken.
run_isolation = full or bool(plan["manifest_files"])
# The HSM seal backends are compiled by NOTHING else in this file: they are off
# by default, `--all-features` is banned, and the isolation job checks each
# member with default features. Three inputs can break them, so all three gate:
#
#   bv-core in lib_pkgs   every `#[cfg(feature = "hsm_*")]` site lives there,
#                         so this covers the code and everything beneath it
#   manifest_files        the Phase 4.5 break was a MISSING dependency, and the
#                         pass-through feature declarations that carry the flag
#                         down to bv-core live in manifests above it. Broad on
#                         purpose, and cheap: any manifest change is already
#                         paying for the isolation job.
#   hsm_files             deploy/container/Containerfile, which is where
#                         BVAULT_FEATURES is declared and where check-hsm reads
#                         the feature list from
run_hsm = (
    full
    or "bv-core" in lib_pkgs
    or bool(plan["manifest_files"])
    or bool(plan["hsm_files"])
)

out = {
    "full": "true" if full else "false",
    "collapse": "true" if collapse else "false",
    "unit_matrix": json.dumps(unit_matrix, separators=(",", ":")),
    "run_unit_matrix": "true" if unit_matrix else "false",
    "integration_matrix": json.dumps(integ_matrix, separators=(",", ":")),
    "run_integration": "true" if integ_matrix else "false",
    "run_gui": "true" if run_gui else "false",
    "run_hiqlite": "true" if run_hiqlite else "false",
    "run_cucumber": "true" if run_cucumber else "false",
    "run_isolation": "true" if run_isolation else "false",
    "run_hsm": "true" if run_hsm else "false",
}

def write(path, text):
    """Append to a GitHub Actions file, or fall back to stdout when run locally.

    Not a `with` block over `sys.stdout` — that closes it, and this is called
    twice.
    """
    if path:
        with open(path, "a") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)


write(
    os.environ.get("GITHUB_OUTPUT"),
    "".join(f"{k}={v}\n" for k, v in out.items()),
)

lines = [
    "## CI plan",
    "",
    f"* changed files: **{plan['n_changed']}** ({plan['n_ignored']} with no Rust test target)",
    f"* affected packages: **{len(lib_pkgs)}/{plan['n_members']}**"
    + (f" — {', '.join(lib_pkgs)}" if lib_pkgs and not collapse else ""),
    "",
    "| job | plan |",
    "|---|---|",
    f"| unit | {'one `--workspace` run (full)' if collapse else f'{len(unit_matrix)} per-package jobs'} |",
    f"| integration | {len(integ_bins)} harness(es) in {n_shards} shard(s) |",
    f"| hiqlite | {'run' if run_hiqlite else 'skipped (bv-storage not affected)'} |",
    f"| cucumber | {'run' if run_cucumber else 'skipped (root crate not affected)'} |",
    f"| isolation | {'run' if run_isolation else 'skipped (no manifest changed)'} |",
    f"| hsm | {'run' if run_hsm else 'skipped (bv-core, manifests and the image recipe all untouched)'} |",
    f"| gui | {'run' if run_gui else 'skipped (gui/ not touched)'} |",
]
if plan["global_hits"]:
    lines += ["", "Full run forced by: " + ", ".join(f"`{f}`" for f in plan["global_hits"])]
if plan["ci_files"]:
    lines += ["", "Full run forced by a workflow change: "
              + ", ".join(f"`{f}`" for f in plan["ci_files"])]

write(os.environ.get("GITHUB_STEP_SUMMARY"), "\n".join(lines) + "\n")
PY
