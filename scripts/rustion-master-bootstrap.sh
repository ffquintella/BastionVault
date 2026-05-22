#!/usr/bin/env bash
# One-shot bootstrap for the Rustion master keypair.
#
# Replaces the ~6-command manual recipe in
# features/rustion-authority-lifecycle.md §0. Idempotent: re-runs
# detect what's already in place (PKI mount, root cert, both roles,
# master config, issued cert) and skip ahead. Exit code 3 means the
# master is already issued; rotate via `bvault rustion master rotate`
# rather than re-running this script.
#
# Usage:
#   bvault login          # populate ~/.vault-token, OR
#   export VAULT_ADDR=... VAULT_TOKEN=...
#   scripts/rustion-master-bootstrap.sh
#
# Flags (all optional):
#   --pki-mount PATH            (default: pki)
#   --ed25519-role NAME         (default: rustion-master-ed25519)
#   --mldsa65-role NAME         (default: rustion-master-mldsa65)
#   --ttl DURATION              (default: 8760h)        role-level TTL
#   --max-ttl DURATION          (default: 87600h)       role-level cap
#   --root-ttl DURATION         (default: 87600h)       root cert lifetime
#   --rotate-grace-secs N       (default: 86400)        grace window
#   --common-name STR           (default: "BastionVault Rustion Master Root")
#   --force                     recreate PKI roles even if they exist
#   --skip-root                 don't generate root (assume already created)
#   -h, --help                  show this help
#
# Exit codes:
#   0  success — master issued
#   1  user/env error (no bvault, no auth, bad flags)
#   2  PKI failure (mount, root, role, or config call failed)
#   3  master already issued (not an error — informational)

set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────
PKI_MOUNT="pki"
ED25519_ROLE="rustion-master-ed25519"
MLDSA65_ROLE="rustion-master-mldsa65"
ROLE_TTL="8760h"
ROLE_MAX_TTL="87600h"
ROOT_TTL="87600h"
ROTATE_GRACE_SECS="86400"
COMMON_NAME="BastionVault Rustion Master Root"
FORCE=0
SKIP_ROOT=0

# Honor BVAULT_* as soft aliases for VAULT_* (the CLI itself reads
# VAULT_ADDR / VAULT_TOKEN; BVAULT_* is a UX convention some operators
# adopt for clarity in shared shells).
if [ -z "${VAULT_ADDR:-}" ] && [ -n "${BVAULT_ADDR:-}" ]; then
  export VAULT_ADDR="$BVAULT_ADDR"
fi
if [ -z "${VAULT_TOKEN:-}" ] && [ -n "${BVAULT_TOKEN:-}" ]; then
  export VAULT_TOKEN="$BVAULT_TOKEN"
fi

usage() {
  sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --pki-mount)         PKI_MOUNT="$2"; shift 2 ;;
    --ed25519-role)      ED25519_ROLE="$2"; shift 2 ;;
    --mldsa65-role)      MLDSA65_ROLE="$2"; shift 2 ;;
    --ttl)               ROLE_TTL="$2"; shift 2 ;;
    --max-ttl)           ROLE_MAX_TTL="$2"; shift 2 ;;
    --root-ttl)          ROOT_TTL="$2"; shift 2 ;;
    --rotate-grace-secs) ROTATE_GRACE_SECS="$2"; shift 2 ;;
    --common-name)       COMMON_NAME="$2"; shift 2 ;;
    --force)             FORCE=1; shift ;;
    --skip-root)         SKIP_ROOT=1; shift ;;
    -h|--help)           usage; exit 0 ;;
    *)
      echo "error: unknown flag '$1'" >&2
      echo "run with --help for usage" >&2
      exit 1
      ;;
  esac
done

# ── Preflight ────────────────────────────────────────────────────────
if ! command -v bvault >/dev/null 2>&1; then
  echo "error: 'bvault' not found on PATH" >&2
  exit 1
fi

echo "==> [1/6] Verifying bvault reachability + auth"
if ! bvault status >/dev/null 2>&1; then
  echo "error: 'bvault status' failed — set VAULT_ADDR and run 'bvault login' first" >&2
  echo "       (BVAULT_ADDR / BVAULT_TOKEN are honored as aliases for the VAULT_* vars)" >&2
  exit 1
fi

# Pre-flight check — if the master is already issued we exit code 3.
# `master export` returns a JSON-ish block; the `issued: ...` line is
# always present. We grep for `true`, tolerating both `--format=json`
# and the plain text default.
if MASTER_EXPORT="$(bvault rustion master export 2>/dev/null)"; then
  if echo "$MASTER_EXPORT" | grep -Eiq '"?issued"?[[:space:]]*[:=][[:space:]]*true'; then
    echo "==> master is already issued — nothing to do"
    echo "    to mint a new keypair, run: bvault rustion master rotate"
    echo "    current export:"
    echo "$MASTER_EXPORT" | sed 's/^/      /'
    exit 3
  fi
fi

# ── 2. PKI mount ─────────────────────────────────────────────────────
echo "==> [2/6] Ensuring PKI mount at '$PKI_MOUNT/'"
MOUNT_PRESENT=0
if bvault secrets list 2>/dev/null | awk '{print $1}' | grep -Eq "^${PKI_MOUNT}/?$"; then
  MOUNT_PRESENT=1
fi
if [ "$MOUNT_PRESENT" -eq 0 ]; then
  if ! bvault secrets enable -path="$PKI_MOUNT" pki; then
    echo "error: failed to enable PKI mount at '$PKI_MOUNT'" >&2
    exit 2
  fi
  echo "    enabled PKI engine at '$PKI_MOUNT/'"
else
  echo "    PKI mount '$PKI_MOUNT/' already present — skipping enable"
fi

# ── 3. Root cert ─────────────────────────────────────────────────────
echo "==> [3/6] Ensuring root certificate"
if [ "$SKIP_ROOT" -eq 1 ]; then
  echo "    --skip-root set — assuming root already exists"
else
  ROOT_PRESENT=0
  if bvault read "${PKI_MOUNT}/cert/ca" >/dev/null 2>&1; then
    ROOT_PRESENT=1
  fi
  if [ "$ROOT_PRESENT" -eq 0 ]; then
    if ! bvault write "${PKI_MOUNT}/root/generate/internal" \
        common_name="$COMMON_NAME" \
        ttl="$ROOT_TTL" >/dev/null; then
      echo "error: failed to generate PKI root at '${PKI_MOUNT}/root/generate/internal'" >&2
      exit 2
    fi
    echo "    generated root CN='$COMMON_NAME' ttl=$ROOT_TTL"
  else
    echo "    root certificate already present — skipping"
  fi
fi

# ── 4. Roles ─────────────────────────────────────────────────────────
echo "==> [4/6] Ensuring PKI roles ($ED25519_ROLE, $MLDSA65_ROLE)"

write_role() {
  local role="$1" key_type="$2"
  if [ "$FORCE" -eq 0 ] && bvault read "${PKI_MOUNT}/roles/${role}" >/dev/null 2>&1; then
    echo "    role '$role' already exists — skipping (use --force to overwrite)"
    return 0
  fi
  if ! bvault write "${PKI_MOUNT}/roles/${role}" \
      key_type="$key_type" \
      allow_any_name=true \
      ttl="$ROLE_TTL" \
      max_ttl="$ROLE_MAX_TTL" >/dev/null; then
    echo "error: failed to write role '$role' (key_type=$key_type)" >&2
    exit 2
  fi
  echo "    wrote role '$role' key_type=$key_type ttl=$ROLE_TTL max_ttl=$ROLE_MAX_TTL"
}

write_role "$ED25519_ROLE" "ed25519"
write_role "$MLDSA65_ROLE" "ml-dsa-65"

# ── 5. Master config ─────────────────────────────────────────────────
echo "==> [5/6] Pointing rustion master at PKI mount + roles"
if ! bvault rustion master config \
    pki_mount="$PKI_MOUNT" \
    pki_role="$ED25519_ROLE" \
    pki_role_pqc="$MLDSA65_ROLE" \
    issuer_ref=default \
    default_ttl_secs=31536000 \
    rotate_grace_secs="$ROTATE_GRACE_SECS" >/dev/null; then
  echo "error: 'bvault rustion master config' failed" >&2
  exit 2
fi
echo "    master config written"

# ── 6. Issue ─────────────────────────────────────────────────────────
echo "==> [6/6] Minting the hybrid master keypair"
if ! ISSUE_OUTPUT="$(bvault rustion master issue 2>&1)"; then
  echo "error: 'bvault rustion master issue' failed:" >&2
  echo "$ISSUE_OUTPUT" | sed 's/^/    /' >&2
  exit 2
fi
echo "$ISSUE_OUTPUT" | sed 's/^/    /'

echo
echo "==> Master bootstrap complete. Export to paste into Rustion authorities:"
bvault rustion master export | sed 's/^/    /'
