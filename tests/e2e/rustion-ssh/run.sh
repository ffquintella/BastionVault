#!/usr/bin/env bash
#
# End-to-end Rustion-mediated SSH driver.
# Phase 3.1 of features/rustion-integration.md.
#
# Walks the stack from cold-start to a successful BV-mediated SSH
# session into the OpenSSH target. Steps map to the trust-model
# diagram in features/rustion-integration.md:
#
#   1. Bring up the three-service stack via docker-compose.
#   2. Wait for BV's HTTP API + Rustion's control plane to answer.
#   3. Enrol the Rustion bastion on BV (export master pubkey, paste
#      it into Rustion's authorities file, register the Rustion
#      target on BV with its KEM pubkey).
#   4. Probe the bastion (`bvault rustion target health`) — confirms
#      the BV ↔ Rustion control-plane link is alive end-to-end.
#   5. Open a BV-mediated session via `bvault rustion session open`.
#      The response carries `{session_id, host, port, ticket}` —
#      the operator's SSH client would then dial Rustion's SSH
#      listener with the ticket as the password.
#   6. ssh to the bastion using the ticket. Rustion verifies it
#      via `rustion-ssh::ticket_auth`, looks up the session, and
#      proxies the bytes to openssh-target with the decrypted
#      credential.
#
# Today the script stops after step 5 + prints the manual ssh
# command for step 6 so an operator can copy/paste it. Once the
# `bastion-vault:phase31-scaffold` + `rustion:phase31-scaffold`
# Dockerfiles land, run.sh chains the final ssh step automatically.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

BV_ADDR="${BV_ADDR:-http://127.0.0.1:8200}"
RUSTION_CONTROL_PLANE="${RUSTION_CONTROL_PLANE:-https://127.0.0.1:9443}"
BV_ROOT_TOKEN="${BV_ROOT_TOKEN:-}"

bold() { printf "\033[1m%s\033[0m\n" "$*"; }
log()  { printf "[e2e] %s\n" "$*"; }
warn() { printf "\033[33m[e2e] %s\033[0m\n" "$*" >&2; }
die()  { printf "\033[31m[e2e] %s\033[0m\n" "$*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

require docker
require docker-compose 2>/dev/null || require docker  # `docker compose` v2 OK too
require bvault
require curl
require jq
require ssh

#───────────────────────────────────────────────────────────────────
# Step 1 — bring up the stack
#───────────────────────────────────────────────────────────────────
bold "Step 1: bring up docker-compose stack"
mkdir -p var/bv var/rustion config/rustion-authorities
if docker compose version >/dev/null 2>&1; then
    DC=(docker compose)
else
    DC=(docker-compose)
fi
"${DC[@]}" up -d --build || warn "compose up failed — the BV + Rustion Dockerfiles aren't yet committed; see README for the Phase-3.1 status"

#───────────────────────────────────────────────────────────────────
# Step 2 — wait for health
#───────────────────────────────────────────────────────────────────
bold "Step 2: wait for BV + Rustion to answer"
wait_for_url() {
    local url=$1 name=$2 tries=60
    while ! curl -k -sf "$url" >/dev/null 2>&1; do
        tries=$((tries-1))
        [ "$tries" -le 0 ] && die "$name never came up at $url"
        sleep 1
    done
    log "$name is up at $url"
}
wait_for_url "$BV_ADDR/v1/sys/health" "BV" || true
wait_for_url "$RUSTION_CONTROL_PLANE/v1/health" "Rustion control plane" || true

#───────────────────────────────────────────────────────────────────
# Step 3 — enrol Rustion on BV
#───────────────────────────────────────────────────────────────────
bold "Step 3: enrol the Rustion target on BV"
if [ -z "$BV_ROOT_TOKEN" ]; then
    warn "BV_ROOT_TOKEN unset — enrolment skipped"
else
    export VAULT_TOKEN="$BV_ROOT_TOKEN"

    # Export BV's master pubkey so we can paste it into Rustion's
    # authorities/ directory.
    log "exporting BV master pubkey"
    bvault --address "$BV_ADDR" rustion master export --format json \
        > config/rustion-authorities/bastion-vault.json

    # Rustion needs the pubkey as a YAML file. Convert via jq.
    jq -r '
      "name: bastion-vault\n" +
      "type: external-vault\n" +
      "pubkey:\n" +
      "  ed25519: \"" + .ed25519_pem + "\"\n" +
      "  mldsa65: \"" + .mldsa65_pem + "\"\n" +
      "fingerprint: \"" + .fingerprint + "\"\n" +
      "allowed_targets: [\"*\"]\n" +
      "allowed_actions: [\"open\", \"renew\", \"terminate\"]\n" +
      "max_session_secs: 43200\n" +
      "replay_window_secs: 300\n" +
      "revoked: false"
    ' config/rustion-authorities/bastion-vault.json \
        > config/rustion-authorities/bastion-vault.yaml
    log "rustion authority record written"

    # Register the Rustion bastion on BV (target name + endpoint +
    # signing pubkey + KEM pubkey). The Phase 3.1 scaffold reads
    # the Rustion-side pubkeys from environment vars the Dockerfile
    # would normally set; here we leave placeholders and skip the
    # actual call so the script doesn't fail when the Dockerfiles
    # aren't yet committed.
    : "${RUSTION_ED25519_PUB:?set RUSTION_ED25519_PUB to the base64-encoded ed25519 pubkey}"
    : "${RUSTION_MLDSA65_PUB:?set RUSTION_MLDSA65_PUB to the base64-encoded mldsa65 pubkey}"
    : "${RUSTION_KEM_PUB:?set RUSTION_KEM_PUB to the base64-encoded ml-kem-768 pubkey}"

    bvault --address "$BV_ADDR" rustion target add \
        --name rustion-e2e \
        --endpoint rustion:9443 \
        --ed25519 "$RUSTION_ED25519_PUB" \
        --mldsa65 "$RUSTION_MLDSA65_PUB" \
        --kem-pubkey "$RUSTION_KEM_PUB" \
        --tags "env=e2e,protocol=ssh" \
        --description "Phase 3.1 docker-compose driver" \
        || warn "target add failed — Rustion may not be running yet"
fi

#───────────────────────────────────────────────────────────────────
# Step 4 — probe
#───────────────────────────────────────────────────────────────────
bold "Step 4: probe bastion via BV"
bvault --address "$BV_ADDR" rustion target health --format json \
    | jq '.targets[] | {id, name, status, last_error, latency_ms_p50}' \
    || warn "probe failed"

#───────────────────────────────────────────────────────────────────
# Step 5 — open a session
#───────────────────────────────────────────────────────────────────
bold "Step 5: open a BV-mediated session to openssh-target"
SESSION_JSON=$(curl -sf "$BV_ADDR/v1/rustion/session/open" \
    -H "X-Vault-Token: ${BV_ROOT_TOKEN:-root}" \
    -H "Content-Type: application/json" \
    -d '{
        "target_host": "target",
        "target_port": 22,
        "target_protocol": "ssh",
        "credential_kind": "ssh-password",
        "credential_username": "deploy",
        "credential_material": "aHVudGVyMg==",
        "ttl_secs": 3600,
        "max_renewals": 3,
        "recording": "always"
    }') || die "session open failed"

echo "$SESSION_JSON" | jq '.'

TICKET=$(echo "$SESSION_JSON" | jq -r '.data.ticket')
HOST=$(echo "$SESSION_JSON" | jq -r '.data.host')
PORT=$(echo "$SESSION_JSON" | jq -r '.data.port')

#───────────────────────────────────────────────────────────────────
# Step 6 — SSH through Rustion
#───────────────────────────────────────────────────────────────────
bold "Step 6: SSH to $HOST:$PORT using ticket as password"
log "Manual: SSHPASS='$TICKET' sshpass -e ssh -o StrictHostKeyChecking=accept-new -p $PORT operator@$HOST"
log "(or, with sshpass not installed, run the above interactively and paste the ticket at the password prompt.)"

# Today the bastion-vault + rustion docker images aren't yet
# committed, so the final ssh step is gated behind the operator
# having those images locally. The Phase 3.1 follow-up adds the
# Dockerfiles + uncomments the line below.
#
# sshpass -p "$TICKET" ssh -o StrictHostKeyChecking=accept-new \
#     -p "$PORT" operator@"$HOST" "uname -a; whoami"

bold "Stack is live — explore with: docker compose logs -f"
