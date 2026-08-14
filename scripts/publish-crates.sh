#!/usr/bin/env bash
#
# Publish the workspace's library crates to the Cloudsmith Cargo registry
# (uox/bastionvault), in dependency order.
#
#   scripts/publish-crates.sh              # dry run — builds + packages, uploads nothing
#   scripts/publish-crates.sh --execute    # for real
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

set -euo pipefail

REGISTRY="${REGISTRY:-uox-bastionvault}"
EXECUTE=0
ONLY=""

# ── Publish order ─────────────────────────────────────────────────────
#
# Topological: a crate may only appear after every workspace crate it
# depends on. A registry rejects a crate whose dependencies it cannot
# resolve, so order is load-bearing, not cosmetic.
#
#   bv-errors           — no workspace deps (Tier 0 substrate: RvError)
#   bv-shamir           -> bv-errors
#   bv-context          -> bv-errors
#   bv-metrics          — no workspace deps
#   bv_plugin_surface   — no workspace deps
#   bv_crypto           — no workspace deps
#   bv-storage          -> bv-errors, bv-metrics, bv_crypto
#   bv-logical          -> bv-errors, bv-context, bv-storage
#   bv-utils            -> bv-errors, bv-shamir, bv-storage, bv-logical, bv_crypto
#   bv-audit            -> bv-errors, bv-logical, bv-storage
#   bv_plugin_manifest  -> bv_plugin_surface
#   bastion-plugin-sdk  -> bv_plugin_surface (optional dep)
#   bastion-plugin-testkit — no workspace deps (wasmtime directly)
#   bv-client           -> bv_plugin_surface
#   bv-plugin-pack      -> bv_crypto, bv_plugin_manifest
#
# `bv_crypto` sits above the Tier 0 leaves here even though it has no
# workspace deps of its own: `bv-storage` (the barriers) and `bv-utils` both
# depend on it, so it has to be on the registry before either.
#
# NOT published, deliberately:
#   bastion_vault       — root crate; see docs/publishing-crates.md
#   bastion-vault-gui   — desktop app, publish = false
CRATES=(
  bv-errors
  bv-shamir
  bv-context
  bv-metrics
  bv_plugin_surface
  bv_crypto
  bv-storage
  bv-logical
  bv-utils
  bv-audit
  bv-kernel-api
  bv_plugin_manifest
  bastion-plugin-sdk
  bastion-plugin-testkit
  bv-client
  bv-plugin-pack
  # Tier 3 engines (Phase 3). Order matters only within the auth backends:
  # userpass needs fido2, approle needs ferrogate, and all of them need
  # bv-auth-audit.
  bv-engine-pki
  bv-engine-kv
  bv-engine-transit
  bv-engine-cert-lifecycle
  bv-engine-ldap
  bv-engine-ssh
  bv-engine-ssh-broker
  bv-engine-totp
  bv-engine-notifications
  bv-engine-files
  bv-engine-resource
  bv-engine-rustion
  bv-auth-audit
  bv-auth-cert
  bv-auth-fido2
  bv-auth-oidc
  bv-auth-saml
  bv-auth-ferrogate
  bv-auth-userpass
  bv-auth-approle
)

while [[ $# -gt 0 ]]; do
  case "$1" in
    --execute)  EXECUTE=1; shift ;;
    --only)     ONLY="$2"; shift 2 ;;
    --registry) REGISTRY="$2"; shift 2 ;;
    -h|--help)  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 64 ;;
  esac
done

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

for crate in "${CRATES[@]}"; do
  version=$(cargo metadata --no-deps --format-version 1 \
    | python3 -c "
import json,sys
m=json.load(sys.stdin)
for p in m['packages']:
    if p['name']=='$crate':
        print(p['version']); break
else:
    sys.exit('$crate not found in workspace metadata')
")
  echo "── $crate $version ─────────────────────────────────────────"

  if [[ $EXECUTE -eq 1 ]]; then
    # No --no-verify: we want the packaged crate compiled from its staged
    # tarball, which is the only check that catches a source file missing
    # from the package (excluded by .gitignore, say).
    cargo publish -p "$crate" --registry "$REGISTRY"
    ok+=("$crate $version")
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
else
  echo "==> published ${#ok[@]} crate(s) to '$REGISTRY'."
fi
