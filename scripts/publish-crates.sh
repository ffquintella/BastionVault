#!/usr/bin/env bash
#
# Publish the workspace's library crates to the Cloudsmith Cargo registry
# (uox/bastionvault), in dependency order.
#
#   scripts/publish-crates.sh              # dry run over every crate
#   scripts/publish-crates.sh --changed    # dry run over only what changed
#   scripts/publish-crates.sh --changed --execute    # for real
#   scripts/publish-crates.sh --only bv_crypto,bv-client
#   scripts/publish-crates.sh --registry some-other-registry
#
# Dry run is the default on purpose: `cargo publish` is irreversible.
# Cargo registries do not allow re-uploading a version, and Cloudsmith's
# delete does not free the version for reuse — a bad publish is fixed by
# yanking and bumping, never by overwriting.
#
# The token is NEVER read from the repo. Cargo picks it up from
# $CARGO_HOME/credentials.toml (written by `cargo login`) or from
# CARGO_REGISTRIES_UOX_BASTIONVAULT_TOKEN. See docs/publishing-crates.md.
#
# ── `--changed`: publish only the crates that changed ─────────────
#
# Each library crate carries its own version and is released on its own
# schedule, so most releases touch a handful of crates rather than all 38.
# `--changed` asks scripts/crates-plan.sh which ones differ from their last
# `<name>-v<version>` release tag and are not already on the registry, and
# publishes exactly those — in the same topological order, because a partial
# release still has to satisfy the registry's resolver.
#
# It refuses to run if the plan says any crate needs a version bump first.
# Publishing a changed crate under an already-published version is impossible
# (the registry rejects it), so failing early with one clear message beats
# failing halfway through an ordered run.
#
# ── Tags are the record of what was published ─────────────────────
#
# On a successful `--execute`, each crate gets a `<name>-v<version>` tag. That
# tag is what the next plan diffs against, so it is not decoration: without it
# the crate looks "never released" forever and gets republished every time.
# Tags are created LOCALLY and never pushed here — pushing is the operator's
# call, and the command is printed at the end.

set -euo pipefail

REGISTRY="${REGISTRY:-uox-bastionvault}"
EXECUTE=0
ONLY=""
CHANGED=0
# A plan computed earlier, instead of computing one here. The plan makes ~38
# HTTPS requests to the registry index, so a pipeline that already has one
# (CI, or `make crates-bump && make crates-publish-changed`) should pass it in
# rather than pay for it twice — and get a decision that cannot have shifted
# under it between the two calls.
PLAN_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --execute)   EXECUTE=1; shift ;;
    --changed)   CHANGED=1; shift ;;
    --only)      ONLY="$2"; shift 2 ;;
    --registry)  REGISTRY="$2"; shift 2 ;;
    --plan-file) PLAN_FILE="$2"; shift 2 ;;
    -h|--help)   sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

# ── Publish order ─────────────────────────────────────────────────────
#
# Topological, derived from `cargo metadata` by scripts/crates-plan.sh, NOT
# hand-maintained. A registry rejects a crate whose dependencies it cannot
# resolve, so order is load-bearing — and the hand-maintained list this
# replaced had already drifted: `bv-core` and `bv-kernel` were created in
# Phase 4.5 carrying `publish = ["uox-bastionvault"]` and were never added to
# it, so every release would have silently skipped the entire kernel.
#
# Which crates are publishable is derived the same way, from the `publish`
# field plus a fixpoint over the dependency graph: a crate cannot ship while
# anything it depends on cannot. That is how `bv-server` and `bvault-cli` drop
# out today (both reach `bastion_vault`, which is `publish = false` while the
# `[patch.crates-io]` forks stand — see docs/publishing-crates.md § Known
# constraints), and how they will rejoin on their own if that changes.
#
# Path-only dev-dependencies are ignored, because cargo strips them from the
# published manifest. Without that rule `bv-kernel` would look unpublishable:
# it dev-depends on `bastion_vault` and `bv-server` to get its test fixtures.
if [[ -n "$PLAN_FILE" ]]; then
  PLAN=$(cat "$PLAN_FILE")
else
  PLAN=$(scripts/crates-plan.sh --json --registry "$REGISTRY")
fi

# `read -r -a` and not `mapfile`: macOS ships bash 3.2 and this script runs on
# a developer's Mac as often as on a Linux runner. Crate names cannot contain
# whitespace, so word-splitting one line is safe here.
plan_field() {
  printf '%s' "$PLAN" | python3 -c "
import json, sys
p = json.load(sys.stdin)
if '$1' == 'order':
    print(' '.join(p['order']))
else:
    print(' '.join(r['name'] for r in p['crates'] if r['action'] == '$1'))"
}

if [[ $CHANGED -eq 1 ]]; then
  needs_bump=$(plan_field bump)
  if [[ -n "$needs_bump" ]]; then
    echo "error: these crates changed but their version is already published:" >&2
    for c in $needs_bump; do echo "         $c" >&2; done
    echo >&2
    echo "       A published version cannot be overwritten, so they have to be" >&2
    echo "       bumped before anything can ship. Run:" >&2
    echo "         make crates-bump                  # patch-bump just those" >&2
    echo "         make crates-bump MINOR=<crate>    # if the change is breaking" >&2
    exit 1
  fi
  read -r -a CRATES <<<"$(plan_field publish)"
  if [[ ${#CRATES[@]} -eq 0 || -z "${CRATES[0]:-}" ]]; then
    echo "==> nothing to publish: every crate is already on '$REGISTRY' at its"
    echo "    current version, and none has changed since."
    exit 0
  fi
else
  read -r -a CRATES <<<"$(plan_field order)"
fi

if [[ -n "$ONLY" ]]; then
  # Preserve the topological order regardless of the order given on the
  # command line — otherwise --only can hand cargo an unresolvable crate.
  IFS=',' read -r -a requested <<< "$ONLY"
  filtered=()
  for c in "${CRATES[@]}"; do
    for r in "${requested[@]}"; do
      [[ "$c" == "$r" ]] && filtered+=("$c")
    done
  done
  if [[ ${#filtered[@]} -eq 0 ]]; then
    echo "error: --only '$ONLY' matched none of: ${CRATES[*]}" >&2
    exit 64
  fi
  CRATES=("${filtered[@]}")
fi

# A dirty tree means the published .crate would not match any commit,
# which makes the artefact unauditable after the fact. cargo enforces
# this itself for tracked files; we check first so the failure is one
# clear message rather than one per crate.
if [[ $EXECUTE -eq 1 ]] && ! git diff-index --quiet HEAD --; then
  echo "error: working tree is dirty — commit or stash before publishing." >&2
  echo "       the published crate must correspond to a real commit." >&2
  git status --short >&2
  exit 1
fi

if [[ $EXECUTE -eq 1 ]]; then
  echo "==> PUBLISHING FOR REAL to '$REGISTRY'  (this cannot be undone)"
  echo "    commit: $(git rev-parse --short HEAD)"
else
  echo "==> DRY RUN against '$REGISTRY' (pass --execute to upload)"
fi
echo "    crates: ${CRATES[*]}"
echo

blocked=()
ok=()
tagged=()

# From the plan we already have, rather than a `cargo metadata` per crate —
# that was 38 resolves of a 1200-crate graph to read 38 strings.
crate_version() {
  printf '%s' "$PLAN" | python3 -c "
import json, sys
for r in json.load(sys.stdin)['crates']:
    if r['name'] == '$1':
        print(r['version']); break
else:
    sys.exit(\"$1 is not in the publish plan\")"
}

for crate in "${CRATES[@]}"; do
  version=$(crate_version "$crate")
  echo "── $crate $version ─────────────────────────────────────────"

  if [[ $EXECUTE -eq 1 ]]; then
    # No --no-verify: we want the packaged crate compiled from its staged
    # tarball, which is the only check that catches a source file missing
    # from the package (excluded by .gitignore, say).
    cargo publish -p "$crate" --registry "$REGISTRY"
    ok+=("$crate $version")

    # Tag what was published, immediately rather than at the end: this is the
    # baseline the NEXT `crates-plan` diffs against, so a run that dies halfway
    # must still leave a correct record for the crates that made it. Without a
    # tag a crate reads as "never released" forever and gets republished on
    # every run.
    #
    # `-f` is deliberately absent. If the tag exists, the version was already
    # published from a different commit and that is a fact worth stopping on,
    # not overwriting.
    if git rev-parse -q --verify "refs/tags/$crate-v$version" >/dev/null; then
      echo "   NOTE: tag $crate-v$version already exists — left as is."
    else
      git tag -a "$crate-v$version" -m "$crate $version" && tagged+=("$crate-v$version")
    fi

    # The index needs a moment to serve a new version before the next
    # crate in the order can resolve it as a dependency.
    echo "   waiting for the index to pick up $crate $version ..."
    sleep 15
  else
    # A dry run cannot succeed for a crate whose workspace dependencies
    # are not on the registry yet: cargo resolves the *published* form of
    # every dependency (registry, not path) before it will stage a
    # tarball, and --no-verify does not skip that step. On a virgin
    # registry that is expected, not a fault — so classify it and carry
    # on instead of aborting the whole run.
    # --allow-dirty on the dry run only. A dry run is for validating that
    # the crate packages and compiles; being able to run it on a work in
    # progress is the whole point. The --execute path deliberately does
    # NOT pass it, and is gated on a clean tree above, because a
    # published artefact must correspond to a real commit.
    log=$(mktemp)
    if cargo publish -p "$crate" --registry "$REGISTRY" --dry-run --allow-dirty >"$log" 2>&1; then
      ok+=("$crate $version")
      tail -3 "$log"
    elif grep -q "no matching package named" "$log" \
      && grep -q "$REGISTRY. index" "$log"; then
      missing=$(grep -o 'no matching package named `[^`]*`' "$log" \
        | head -1 | sed 's/.*`\(.*\)`/\1/')
      echo "   SKIPPED — needs '$missing' on the registry first (publish order)."
      blocked+=("$crate (waiting on $missing)")
    else
      echo "   FAILED:"
      cat "$log"
      rm -f "$log"
      exit 1
    fi
    rm -f "$log"
  fi
  echo
done

echo "════ summary ════"
[[ ${#ok[@]} -gt 0 ]] && printf '  validated: %s\n' "${ok[@]}"
if [[ ${#blocked[@]} -gt 0 ]]; then
  printf '  deferred:  %s\n' "${blocked[@]}"
  echo
  echo "  'deferred' is normal until the registry has the dependency."
  echo "  A real --execute run publishes in order, so each becomes"
  echo "  resolvable as its turn arrives."
fi
echo
if [[ $EXECUTE -eq 0 ]]; then
  echo "==> DRY RUN — nothing was uploaded. Re-run with --execute to publish."
  if [[ $CHANGED -eq 0 ]]; then
    echo "    This validated every publishable crate. For a release, --changed"
    echo "    narrows it to what actually moved."
  fi
else
  echo "==> published ${#ok[@]} crate(s) to '$REGISTRY'."
  if [[ ${#tagged[@]} -gt 0 ]]; then
    echo
    echo "    Tagged locally (${#tagged[@]}):"
    printf '      %s\n' "${tagged[@]}"
    echo
    # Not pushed automatically. Pushing publishes the release record to
    # everyone, and that is the operator's call, not this script's — the
    # upload already happened and is irreversible, but the tags are still
    # local and reviewable.
    echo "    These are LOCAL. Push them so the next release has a baseline:"
    echo "      git push origin ${tagged[*]}"
    echo "    or:  make crates-tag-push"
  fi
fi
