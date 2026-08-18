#!/usr/bin/env bash
#
# Run only the tests a change can possibly have broken.
#
#   scripts/test-changed.sh                       # uncommitted work (tracked + untracked)
#   scripts/test-changed.sh --base main           # ...plus everything since merge-base(main)
#   scripts/test-changed.sh --list                # print the plan, build nothing
#   scripts/test-changed.sh --json                # print the plan as JSON, build nothing
#   scripts/test-changed.sh --direct              # changed packages only, no dependents
#   scripts/test-changed.sh --pkg bv-engine-pki   # explicit seed, ignore git entirely
#   scripts/test-changed.sh -- issue_cert         # extra args go to nextest (filter, -E, ...)
#
# WHY THIS EXISTS
#
# `make test` is `cargo nextest run --workspace --lib --bins`. On this tree that
# links ~40 test harnesses, five of which are 200 MB+ (the root crate, bv-server,
# the bvault bin, ...). Paying that on every edit is the single largest sink of
# wall-clock time in the inner dev loop, and almost all of it is spent linking
# and running tests the edit provably cannot reach.
#
# AGENTS.md §3 already tells a developer to work the blast radius out by hand and
# run `cargo nextest run -p <pkg> --lib`. This script derives it from the
# dependency graph instead of from memory, so it cannot be under-scoped by
# forgetting that (say) `bastion_vault` dev-depends on `bv-server`.
#
# HOW THE SET IS DERIVED
#
#   1. changed files = `git diff --name-only HEAD` + untracked-not-ignored
#      (+ `git diff --name-only $(git merge-base <base> HEAD)` with --base)
#   2. file -> package by LONGEST matching manifest directory. The root package
#      `bastion_vault` sits at the repo root, so it is the fallback owner for
#      anything not inside another member's directory.
#   3. package -> reverse-dependency closure over workspace members, following
#      normal, dev AND build dependencies. Dev deps matter: the root crate
#      dev-depends on `bv-server`, so editing bv-server must re-run the root
#      crate's lib tests.
#   4. `bastion-vault-gui` is dropped — same exclusion as `make test`.
#
# Step 3 is the conservative half and it is not free: `bv-kernel-api` has 24
# reverse dependencies, so editing it legitimately reaches most of the tree.
# `--direct` skips step 3 and runs only the packages you actually edited. Use it
# while iterating inside one crate; drop it before you hand the change off, and
# never use it as the last run before a commit that changes a public API.
#
# WHAT FORCES A FULL RUN
#
# Some files are not owned by one package in any useful sense: a
# `[workspace.dependencies]` bump or a lockfile change can alter what every crate
# compiles against. Those short-circuit to the full suite rather than guessing:
#
#   Cargo.lock   Cargo.toml (root: BOTH the workspace and the root package
#   manifest)    .cargo/config.toml   rust-toolchain.toml   .config/nextest.toml
#
# If you know a root-manifest edit was package-local, seed the run yourself with
# `--pkg bastion_vault` rather than arguing with the heuristic.
#
# WHAT IS DELIBERATELY NOT COVERED
#
#   * `tests/` integration binaries — `--tests` links ~30 harnesses over the full
#     graph. Changes under `tests/` are reported and the exact `--test <name>`
#     command is printed, but they are not run for you.
#   * doctests, hiqlite, cucumber, the GUI frontend, plugin ABI parity — all
#     release-gate suites. See `make test-release`.
#
# This is a WALL-CLOCK optimisation, not a coverage policy. It narrows the inner
# loop. It does not replace the release gate, and nothing here may make
# `make test-release` narrower.
#
# `--json` AND THE CI MATRIX
#
# Phase 5 of roadmaps/workspace-decomposition.md builds the CI job matrix from
# THIS graph rather than from a second, hand-maintained list of path globs. That
# is deliberate: the roadmap sketched `dorny/paths-filter`, and this repo has
# already mis-measured its own dependency graph three separate times with three
# different bad regexes (see the roadmap's "the third measurement error"). A
# path-glob filter is a fourth copy of the graph that drifts silently the first
# time a crate gains a dependency. `cargo metadata` cannot drift.
#
# So `--json` prints the whole plan — including things the interactive run only
# reports as prose — and scripts/ci-plan.sh turns it into GitHub Actions matrix
# outputs. The extra fields exist for that consumer:
#
#   integration_bins       `#[test]` harnesses under tests/ owned by an affected
#                          package, minus the two nextest cannot enumerate
#   all_integration_bins   the same, for every member — CI's full-run plan
#   needs_bvault_bin       affected packages whose lib tests spawn
#                          target/debug/bvault
#   manifest_files         any Cargo.toml / Cargo.lock hit, which gates the
#                          per-crate isolation check
#   ci_files               .github/** hits, which the interactive run ignores and
#                          CI must not (you cannot validate a workflow edit with
#                          an empty matrix)
#
# Adding a field here is cheap; teaching CI a second way to compute one is not.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

BASE=""
LIST_ONLY=0
JSON_ONLY=0
DIRECT=0
PROFILE="quick"
SEED_PKGS=()
NEXTEST_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)           BASE="${2:?--base needs a git ref}"; shift 2 ;;
    --list|--dry-run) LIST_ONLY=1; shift ;;
    --json)           JSON_ONLY=1; shift ;;
    --direct)         DIRECT=1; shift ;;
    --profile)        PROFILE="${2:?--profile needs a nextest profile name}"; shift 2 ;;
    --pkg)            SEED_PKGS+=("${2:?--pkg needs a package name}"); shift 2 ;;
    --)               shift; NEXTEST_ARGS=("$@"); break ;;
    -h|--help)        sed -n '2,94p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "test-changed: unknown argument '$1' (use -- to pass args to nextest)" >&2; exit 2 ;;
  esac
done

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# ── Collect the changed-file set ──────────────────────────────────
#
# `--pkg` REPLACES this rather than adding to it: it exists so you can test a
# crate whose files you have not touched (or override the full-run heuristic),
# and unioning it with a dirty tree would silently defeat both.
if [[ ${#SEED_PKGS[@]} -gt 0 ]]; then
  : >"$WORK/changed"
else
  {
    # Tracked files differing from HEAD: staged and unstaged in one shot.
    git diff --name-only HEAD
    # Untracked-but-not-ignored: a brand new src/foo.rs is exactly the kind of
    # change that needs testing, and it is invisible to `git diff`.
    git ls-files --others --exclude-standard
    if [[ -n "$BASE" ]]; then
      # Everything this branch added on top of the base, so a run late in a
      # branch still covers what was committed earlier in it.
      MERGE_BASE=$(git merge-base "$BASE" HEAD) || {
        echo "test-changed: '$BASE' is not a valid git ref" >&2; exit 2; }
      git diff --name-only "$MERGE_BASE"
    fi
  } | sort -u >"$WORK/changed"
fi

# `cargo metadata` WITH deps (no --no-deps) so `resolve.nodes` is populated —
# that is the only place the resolved edges live. It reads Cargo.lock and the
# manifests; it compiles nothing.
cargo metadata --format-version 1 >"$WORK/meta.json"

# Emits a shell-sourceable plan. Keeping the graph work in python and the
# process orchestration in bash keeps both halves readable under incident
# conditions, which is the house rule (AGENTS.md §7).
python3 - "$WORK" "$DIRECT" "${SEED_PKGS[@]+"${SEED_PKGS[@]}"}" <<'PY'
import json, os, sys, shlex

work, direct, *seed_pkgs = sys.argv[1:]
direct = direct == "1"

with open(os.path.join(work, "meta.json")) as fh:
    md = json.load(fh)

root = md["workspace_root"]
member_ids = set(md["workspace_members"])
by_id = {p["id"]: p for p in md["packages"]}
members = {i: by_id[i] for i in member_ids if i in by_id}
name_of = {i: p["name"] for i, p in members.items()}
known = set(name_of.values())

# Manifest directory relative to the workspace root, longest first so the root
# package (dir "") only ever wins as the fallback.
dirs = sorted(
    (
        ("" if (d := os.path.relpath(os.path.dirname(p["manifest_path"]), root)) == "." else d + "/"),
        p["name"],
    )
    for p in members.values()
)
dirs.sort(key=lambda t: -len(t[0]))

has_lib = {
    p["name"]
    for p in members.values()
    if any(k in ("lib", "rlib", "proc-macro") for t in p["targets"] for k in t["kind"])
}

# Integration-test harnesses, by owning package: every `tests/*.rs` is its own
# binary and its own full link of the graph below it. Two are unrunnable under
# nextest and are excluded here rather than in the consumer, so the exclusion
# lives next to the reason:
#
#   cucumber_hiqlite            `harness = false` — a plain main(), not libtest,
#                               so nextest cannot enumerate its cases.
#   hiqlite_ha_fault_injection  hands itself TCP ports from a process-global
#                               atomic; process-per-test collides on every one.
#
# Both mirror `default-filter` in .config/nextest.toml and both have their own
# make target (`test-cucumber`, `test-hiqlite`).
NEXTEST_CANNOT_RUN = {"cucumber_hiqlite", "hiqlite_ha_fault_injection"}
test_bins = {
    p["name"]: sorted(
        t["name"]
        for t in p["targets"]
        if "test" in t["kind"] and t["name"] not in NEXTEST_CANNOT_RUN
    )
    for p in members.values()
}

# Packages whose *lib* tests spawn the real `bvault` executable rather than
# calling the CLI in-process — `test_utils::get_project_binary_path()` resolves
# it as target/<profile>/bvault, and building a test harness does not produce
# it. A developer's tree usually has a stale one lying around; a CI runner does
# not, and the failure reads "No such file or directory (os error 2)".
#
# Re-derive after adding a caller — every hit outside test_utils.rs itself
# belongs to a package that needs the binary:
#     grep -rln get_project_binary_path --include='*.rs' src crates
BIN_DEP_PKGS = {"bastion_vault", "bv-server", "bvault-cli"}

# Bin targets that actually contain tests. Every other [[bin]] in this workspace
# links a full ~200 MB test harness to run zero tests, so `--bins` is only worth
# paying for these. Today: bvault-cli's main.rs is a 19-line delegate to its lib
# and bin/bv_ssh_helper.rs has no test module, so only bv-plugin-pack qualifies.
#
# Re-derive after adding a #[cfg(test)] to a bin:
#     cargo nextest list --workspace --exclude bastion-vault-gui --bins
BIN_TEST_PKGS = {"bv-plugin-pack"}

# Same exclusion as the Makefile's TEST_SCOPE.
EXCLUDED = {"bastion-vault-gui"}

# Files whose blast radius is "everything". See the header comment.
GLOBAL = {
    "Cargo.lock",
    "Cargo.toml",
    ".cargo/config.toml",
    "rust-toolchain.toml",
    ".config/nextest.toml",
}

# No effect on any Rust test target. A prefix list rather than a suffix rule, so
# that e.g. src/**/*.md is still (harmlessly) attributed to its crate instead of
# being silently dropped.
IGNORED_PREFIXES = (
    "docs/", "features/", "roadmaps/", ".github/", "deploy/", "installers/",
    "third_party/", "IronRDP/", "plugins-ext/", "target/", "node_modules/",
    "gui/node_modules/", "gui/dist/",
)

# Ignored for *test selection* — a workflow edit cannot break a Rust test — but
# reported separately, because CI has the opposite need: a PR that only edits
# .github/workflows/tests.yml must still run enough of the suite to show that
# the edit works. scripts/ci-plan.sh forces a full run on these.
CI_PREFIXES = (".github/",)
IGNORED_EXACT = {
    "README.md", "CHANGELOG.md", "AGENTS.md", "CLAUDE.md", "agent.md",
    "roadmap.md", "LICENSE", "Makefile", ".gitignore",
}

with open(os.path.join(work, "changed")) as fh:
    files = [l.strip() for l in fh if l.strip()]

global_hits, gui_frontend, integration, ignored = [], [], [], 0
ci_files = []
seeds = set()

for f in files:
    if f.startswith(CI_PREFIXES):
        ci_files.append(f)
        ignored += 1
    elif f in GLOBAL:
        global_hits.append(f)
    elif f in IGNORED_EXACT or f.startswith(IGNORED_PREFIXES):
        ignored += 1
    elif f.startswith("gui/") and not f.startswith("gui/src-tauri/"):
        gui_frontend.append(f)
    else:
        if f.startswith("tests/"):
            integration.append(f)
        for prefix, name in dirs:
            if f.startswith(prefix):
                seeds.add(name)
                break

for p in seed_pkgs:
    if p not in known:
        sys.exit(f"test-changed: '{p}' is not a workspace member")
    seeds.add(p)
    global_hits.clear()   # an explicit seed overrides the full-run heuristic

# ── Reverse-dependency closure over workspace members ─────────────
#
# resolve.nodes holds forward edges. Invert them, keep only member->member
# edges, and follow every dep_kind: a dev-dependency is a real rebuild+rerun
# edge for the depending crate's tests, which is the whole point.
rdeps = {n: set() for n in known}
for node in md["resolve"]["nodes"]:
    if node["id"] not in members:
        continue
    dependent = name_of[node["id"]]
    for dep in node["deps"]:
        if dep["pkg"] in members:
            rdeps[name_of[dep["pkg"]]].add(dependent)

if direct:
    affected = set(seeds)
else:
    affected, queue = set(), list(seeds)
    while queue:
        p = queue.pop()
        if p in affected:
            continue
        affected.add(p)
        queue.extend(rdeps.get(p, ()))

affected -= EXCLUDED
lib_pkgs = sorted(p for p in affected if p in has_lib)
bin_pkgs = sorted(affected & BIN_TEST_PKGS)
integ_bins = sorted(b for p in affected for b in test_bins.get(p, ()))
bvault_bin = sorted(affected & BIN_DEP_PKGS)


def emit(fh, key, value):
    fh.write(f"{key}={shlex.quote(str(value))}\n")


with open(os.path.join(work, "plan.sh"), "w") as fh:
    emit(fh, "PLAN_FULL", "1" if global_hits else "0")
    emit(fh, "PLAN_GLOBAL_HITS", " ".join(sorted(global_hits)))
    emit(fh, "PLAN_LIB_PKGS", " ".join(lib_pkgs))
    emit(fh, "PLAN_BIN_PKGS", " ".join(bin_pkgs))
    emit(fh, "PLAN_SEEDS", " ".join(sorted(seeds - EXCLUDED)))
    emit(fh, "PLAN_GUI_FILES", " ".join(sorted(gui_frontend)))
    emit(fh, "PLAN_INTEG_FILES", " ".join(sorted(integration)))
    emit(fh, "PLAN_N_CHANGED", len(files))
    emit(fh, "PLAN_N_IGNORED", ignored)
    emit(fh, "PLAN_N_MEMBERS", len(members) - len(EXCLUDED))

# The same plan, losslessly, for scripts/ci-plan.sh. Written unconditionally —
# it costs nothing and it means the JSON can never describe a different graph
# from the one the interactive run just printed.
with open(os.path.join(work, "plan.json"), "w") as fh:
    json.dump(
        {
            "full": bool(global_hits),
            "global_hits": sorted(global_hits),
            "lib_pkgs": lib_pkgs,
            "bin_pkgs": bin_pkgs,
            "seeds": sorted(seeds - EXCLUDED),
            "gui_files": sorted(gui_frontend),
            "integration_files": sorted(integration),
            "integration_bins": integ_bins,
            # Every runnable harness in the workspace, not just the affected
            # ones. CI needs this for its full-run plan, and deriving it there
            # would mean a second copy of the NEXTEST_CANNOT_RUN exclusion.
            "all_integration_bins": sorted(
                b for bins in test_bins.values() for b in bins
            ),
            "needs_bvault_bin": bvault_bin,
            "ci_files": sorted(ci_files),
            # The container image's build recipe. `deploy/` is in
            # IGNORED_PREFIXES because a Containerfile cannot break a Rust test
            # — but it declares BVAULT_FEATURES, which is the ONLY place in the
            # repo that turns the HSM seal backends on, and scripts/check-hsm.sh
            # reads it. Reported so scripts/ci-plan.sh can gate the hsm job on a
            # change to it; still ignored for test selection.
            "hsm_files": sorted(
                f for f in files if f == "deploy/container/Containerfile"
            ),
            # Any manifest, not just the root one GLOBAL catches. A
            # `crates/*/Cargo.toml` edit is package-local for test *selection*
            # but not for feature unification, which is what the isolation job
            # exists to catch — see Phase 4.5's `log/std` bug.
            "manifest_files": sorted(
                f for f in files if f == "Cargo.lock" or f.endswith("Cargo.toml")
            ),
            "n_changed": len(files),
            "n_ignored": ignored,
            "n_members": len(members) - len(EXCLUDED),
        },
        fh,
        indent=2,
        sort_keys=True,
    )
PY

# `--json` is a pure query: the plan on stdout, nothing else, and no exit code
# that means "a full run is required" — the consumer reads the `full` field and
# decides. Everything below this line is the interactive presentation.
if [[ "$JSON_ONLY" == "1" ]]; then
  cat "$WORK/plan.json"
  exit 0
fi

# shellcheck source=/dev/null
. "$WORK/plan.sh"

if [[ ${#SEED_PKGS[@]} -gt 0 ]]; then
  echo "==> seeded from --pkg: ${SEED_PKGS[*]}"
else
  echo "==> $PLAN_N_CHANGED changed file(s)${BASE:+, working tree + since merge-base $BASE}"
fi

if [[ "$PLAN_FULL" == "1" ]]; then
  echo ""
  echo "    Full run required — these change what the whole workspace compiles against:"
  for f in $PLAN_GLOBAL_HITS; do echo "      $f"; done
  echo ""
  echo "    Run:  make test"
  echo "    Or seed the narrow run yourself:  scripts/test-changed.sh --pkg <name>"
  exit 1
fi

[[ -n "$PLAN_GUI_FILES" ]] && \
  echo "    GUI frontend touched — not covered here. Run: make gui-test"

if [[ -n "$PLAN_INTEG_FILES" ]]; then
  echo "    tests/ touched — integration binaries are not run here:"
  for f in $PLAN_INTEG_FILES; do
    echo "      cargo nextest run --test $(basename "$f" .rs)"
  done
fi

if [[ -z "$PLAN_LIB_PKGS" && -z "$PLAN_BIN_PKGS" ]]; then
  echo "    No Rust test target is affected. Nothing to run."
  exit 0
fi

N_AFFECTED=$(echo $PLAN_LIB_PKGS $PLAN_BIN_PKGS | wc -w | tr -d ' ')
N_SEEDS=$(echo $PLAN_SEEDS | wc -w | tr -d ' ')
if [[ "$DIRECT" == "1" ]]; then
  echo "    Changed: $N_AFFECTED/$PLAN_N_MEMBERS package(s) — --direct, reverse dependencies NOT run"
else
  echo "    Changed: $N_SEEDS -> with dependents: $N_AFFECTED/$PLAN_N_MEMBERS package(s)"
fi
for p in $PLAN_LIB_PKGS $PLAN_BIN_PKGS; do echo "      $p"; done

# Past ~3/4 of the workspace the narrow run has stopped being an optimisation
# and is just `make test` with extra steps. Say so rather than letting someone
# believe they scoped it down.
if [[ "$N_AFFECTED" -gt $(( PLAN_N_MEMBERS * 3 / 4 )) ]]; then
  echo ""
  echo "    NOTE: that is most of the workspace — a low-tier crate changed."
  echo "          \`make test\` costs about the same and covers the bins too."
fi

LIB_FLAGS=(); for p in $PLAN_LIB_PKGS; do LIB_FLAGS+=(-p "$p"); done
BIN_FLAGS=(); for p in $PLAN_BIN_PKGS; do BIN_FLAGS+=(-p "$p"); done

if [[ "$LIST_ONLY" == "1" ]]; then
  echo ""
  [[ -n "$PLAN_LIB_PKGS" ]] && \
    echo "    would run: cargo nextest run --profile $PROFILE ${LIB_FLAGS[*]} --lib ${NEXTEST_ARGS[*]+${NEXTEST_ARGS[*]}}"
  [[ -n "$PLAN_BIN_PKGS" ]] && \
    echo "    would run: cargo nextest run --profile $PROFILE ${BIN_FLAGS[*]} --bins ${NEXTEST_ARGS[*]+${NEXTEST_ARGS[*]}}"
  exit 0
fi

# ── Warn about a concurrent cargo before spending time on one ─────
#
# All cargo invocations share one `target/` build lock, and the loser blocks for
# as long as the winner takes — it does not run in parallel. A narrow run that
# should take seconds then takes minutes, and the output looks like a slow test
# suite rather than a queue. Name it instead.
#
# rust-analyzer is deliberately not a false positive here: .vscode/settings.json
# sets `rust-analyzer.cargo.targetDir`, so its on-save check holds a different
# lock. Anything this catches is a real second build.
if command -v pgrep >/dev/null 2>&1; then
  # `|| true` is load-bearing under `set -o pipefail`: pgrep exits 1 when it
  # matches nothing, and so does `grep -v` when it emits no lines — so on a
  # quiet machine, which is the normal case, the pipeline returned 1, the
  # assignment failed, and `set -e` killed the run HERE, after printing the
  # plan and before running a single test. `--json` (and therefore all of CI)
  # returns above this point, which is why it stayed hidden.
  OTHER=$(pgrep -f '/cargo (build|check|test|nextest|clippy|run|doc)' 2>/dev/null \
          | grep -v "^$$\$" | wc -l | tr -d ' ' || true)
  if [[ "${OTHER:-0}" -gt 0 ]]; then
    echo ""
    echo "    WARNING: $OTHER other cargo process(es) are running."
    echo "             They share this tree's target/ build lock, so this run will"
    echo "             queue behind them rather than run alongside (AGENTS.md §5)."
  fi
fi

echo ""
# ONE cargo invocation at a time — they share the target/ build lock (AGENTS.md §5).
[[ -n "$PLAN_LIB_PKGS" ]] && \
  cargo nextest run --profile "$PROFILE" "${LIB_FLAGS[@]}" --lib ${NEXTEST_ARGS[@]+"${NEXTEST_ARGS[@]}"}

[[ -n "$PLAN_BIN_PKGS" ]] && \
  cargo nextest run --profile "$PROFILE" "${BIN_FLAGS[@]}" --bins ${NEXTEST_ARGS[@]+"${NEXTEST_ARGS[@]}"}

exit 0
