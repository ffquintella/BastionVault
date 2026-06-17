#!/usr/bin/env bash
#
# End-to-end Rustion-mediated SSH driver.
# (features/rustion-integration.md + features/connect-only-access.md)
#
# Walks the three-service stack from cold-start to a real BV-mediated
# SSH session into the OpenSSH target, then exercises the *connect-only*
# path (a token that may open a session but may NOT read the credential).
#
# Flow:
#   1.  bring up bastion-vault; wait for its API.
#   2.  init + unseal (1-of-1) over the API; capture the root token.
#   3.  issue + export BV's master signing pubkey; write the Rustion
#       authority record (correct schema: pubkey_*_b64 = base64 of the
#       raw key bytes — NOT PEM).
#   4.  bring up rustion (authority now pinned) + openssh-target.
#   5.  enrol the bastion on BV: KEM pubkey from the bind-mounted
#       identity.pub, TLS leaf pinned so BV accepts the self-signed
#       control plane. Probe health.
#   6.  create a resource + an ssh-password secret.
#   7.  classic open (root token, raw credential) → SSH through.
#   8.  connect-only open: a connect-only token is *denied* a direct
#       read of the secret (403) but its rustion/v2/session/open resolves
#       the credential server-side and proxies an SSH session through the
#       bastion → SSH through with no client-side credential read.
#
# Requirements: docker (compose v2), curl, jq, openssl, ssh, sshpass.
# Override BV_ROOT_TOKEN to reuse an already-initialised var/bv.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

BV_ADDR="${BV_ADDR:-http://127.0.0.1:8200}"
# Host-facing Rustion endpoints (compose publishes these on localhost).
RUSTION_CP="${RUSTION_CP:-https://127.0.0.1:9443}"
RUSTION_SSH_HOST="${RUSTION_SSH_HOST:-127.0.0.1}"
RUSTION_SSH_PORT="${RUSTION_SSH_PORT:-2222}"
# In-network endpoint BV uses to reach the bastion control plane.
RUSTION_ENDPOINT="${RUSTION_ENDPOINT:-rustion:9443}"

RESOURCE="${RESOURCE:-ssh-target}"
SECRET_KEY="${SECRET_KEY:-deploy-login}"
TARGET_USER="${TARGET_USER:-deploy}"
TARGET_PASS="${TARGET_PASS:-hunter2}"
# The linuxserver/openssh-server image listens on 2222 inside the
# container (not 22), so the bastion dials the target on 2222.
TARGET_PORT="${TARGET_PORT:-2222}"

BV_ROOT_TOKEN="${BV_ROOT_TOKEN:-}"

bold() { printf "\n\033[1m%s\033[0m\n" "$*"; }
log()  { printf "[e2e] %s\n" "$*"; }
warn() { printf "\033[33m[e2e] %s\033[0m\n" "$*" >&2; }
die()  { printf "\033[31m[e2e] %s\033[0m\n" "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
require docker; require curl; require jq; require openssl; require ssh

# Bound a command with a wall-clock timeout when a timeout(1) is available
# (GNU coreutils `timeout`, or `gtimeout` on macOS via brew). Falls back to
# running unbounded — the SSH probe feeds `exit` over stdin, so it
# terminates on its own; the timeout is only a safety net for a wedged proxy.
if command -v timeout >/dev/null 2>&1;  then TIMEOUT=(timeout 40)
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT=(gtimeout 40)
else TIMEOUT=(env); fi   # `env` is a transparent prefix (safe under bash 3.2 + set -u)

if docker compose version >/dev/null 2>&1; then DC=(docker compose); else DC=(docker-compose); fi

# Opt-in two-instance failover phase (Step 9). When set, every compose
# command also loads the overlay that adds `rustion-2`, and run.sh runs
# the kill-primary failover assertions after the main flow.
E2E_FAILOVER="${E2E_FAILOVER:-}"
RUSTION2_CP="${RUSTION2_CP:-https://127.0.0.1:9444}"
RUSTION2_ENDPOINT="${RUSTION2_ENDPOINT:-rustion-2:9443}"
if [ -n "$E2E_FAILOVER" ]; then
    DC+=(-f docker-compose.yaml -f docker-compose.failover.yaml)
    log "E2E_FAILOVER set — rustion-2 overlay enabled"
fi

# curl helper: prints "<http_status>\n<body>"; callers split with read.
api() {
    local method=$1 path=$2; shift 2
    curl -sk -o /tmp/bv-body.$$ -w '%{http_code}' -X "$method" "$BV_ADDR$path" "$@"
    printf '\n'
    cat /tmp/bv-body.$$; rm -f /tmp/bv-body.$$
}

# Strip PEM armour → single-line base64 body (BV armours raw key bytes,
# so the body IS base64(raw pubkey) — exactly the authority record shape).
pem_body() { grep -v -- '-----' | tr -d '[:space:]'; }

#───────────────────────────────────────────────────────────────────
bold "Step 1 — bring up bastion-vault"
mkdir -p var/bv var/rustion config/rustion-authorities
"${DC[@]}" up -d --build bastion-vault
log "waiting for BV API…"
# GET /v1/sys/init answers 200 even before init; seal-status/health 500/501
# until the vault is initialised, so they are unusable as a liveness probe.
tries=90
until curl -sf "$BV_ADDR/v1/sys/init" >/dev/null 2>&1; do
    tries=$((tries-1)); [ "$tries" -le 0 ] && die "BV never answered at $BV_ADDR"
    sleep 1
done
log "BV is up"

#───────────────────────────────────────────────────────────────────
bold "Step 2 — init + unseal"
if [ -n "$BV_ROOT_TOKEN" ]; then
    log "BV_ROOT_TOKEN supplied — skipping init, assuming existing var/bv"
    ROOT="$BV_ROOT_TOKEN"
else
    IFS=$'\n' read -r -d '' code body < <(
        api POST /v1/sys/init -H 'Content-Type: application/json' \
            -d '{"secret_shares":1,"secret_threshold":1}'; printf '\0')
    if [ "$code" != "200" ]; then
        die "init failed (HTTP $code): $body — already initialised? wipe ./var/bv or pass BV_ROOT_TOKEN."
    fi
    ROOT=$(echo "$body" | jq -r '.root_token')
    KEY=$(echo "$body"  | jq -r '.keys[0]')
    [ -n "$ROOT" ] && [ "$ROOT" != null ] || die "no root_token in init response: $body"
    api POST /v1/sys/unseal -H 'Content-Type: application/json' \
        -d "{\"key\":\"$KEY\"}" >/dev/null
    log "initialised + unsealed"
fi
echo "root token: $ROOT"
RT=(-H "X-Vault-Token: $ROOT")

#───────────────────────────────────────────────────────────────────
bold "Step 3 — materialise + export BV master pubkey; pin it as a Rustion authority"
# The master signing key is minted lazily by the first session-open
# (`get_or_init_signing_key`, the Phase-2 ephemeral stub) — `master/issue`
# proper needs a configured PKI mount + PQC role, which this harness does
# not set up. Prime it with a deliberately-doomed open (no bastion enrolled
# yet): the handler mints + persists the keypair *before* it looks for a
# target, then fails at dispatch — which we ignore.
log "priming master signing key (one expected-to-fail open)…"
api POST /v1/rustion/session/open "${RT[@]}" -H 'Content-Type: application/json' \
    -d '{"target_host":"target","target_port":22,"target_protocol":"ssh",
         "credential_kind":"ssh-password","credential_username":"x",
         "credential_material":"eA==","ttl_secs":60}' >/dev/null 2>&1 || true

PUB=$(curl -sk "$BV_ADDR/v1/rustion/master/pubkey" "${RT[@]}")
ED_B64=$(echo "$PUB" | jq -r '.data.ed25519_pem // .ed25519_pem' | pem_body)
ML_B64=$(echo "$PUB" | jq -r '.data.mldsa65_pem // .mldsa65_pem' | pem_body)
FP=$(echo "$PUB"     | jq -r '.data.fingerprint // .fingerprint')
[ -n "$ED_B64" ] || die "could not derive ed25519 pubkey from: $PUB"
log "master fingerprint: $FP"

# Rustion's on-disk authority schema (rustion-control-plane authority_disk.rs):
# base64 of the RAW key bytes, not PEM.
cat > config/rustion-authorities/bastion-vault.yaml <<YAML
schema_version: 1
name: bastion-vault
pubkey_ed25519_b64: "$ED_B64"
pubkey_mldsa65_b64: "$ML_B64"
allowed_targets: ["*"]
allowed_actions: ["open", "renew", "kill"]
max_session_secs: 43200
replay_window_secs: 300
revoked: false
YAML
log "authority record written to config/rustion-authorities/bastion-vault.yaml"

#───────────────────────────────────────────────────────────────────
bold "Step 4 — bring up rustion + openssh-target"
# Rustion's control plane requires its TLS cert/key to already exist
# (unlike the identity keypair, they are not auto-generated). Mint a
# self-signed pair into the bind-mounted control-plane/ dir, and
# pre-create the other writable dirs the config points at.
mkdir -p var/rustion/control-plane var/rustion/users var/rustion/targets \
         var/rustion/roles var/rustion/audit var/rustion/audit-keys \
         var/rustion/recordings
# Seed a cert-auth-only admin user so rustion's first-run bootstrap
# doesn't try to prompt for an admin password on a TTY-less container
# (the BV-ticket auth path bypasses the user store entirely anyway).
if [ ! -e var/rustion/users/admin.yaml ]; then
    cat > var/rustion/users/admin.yaml <<'YAML'
username: admin
enabled: true
roles:
  - admin
allowed_targets: []
mfa: {}
YAML
fi
if [ ! -s var/rustion/control-plane/tls.crt ]; then
    log "minting self-signed control-plane TLS cert"
    openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
        -keyout var/rustion/control-plane/tls.key \
        -out    var/rustion/control-plane/tls.crt \
        -subj "/CN=rustion" \
        -addext "subjectAltName=DNS:rustion,DNS:localhost,IP:127.0.0.1" \
        >/dev/null 2>&1
fi
"${DC[@]}" up -d --build rustion openssh-target
log "waiting for Rustion control plane…"
tries=90
until curl -ksf "$RUSTION_CP/v1/health" >/dev/null 2>&1; do
    tries=$((tries-1)); [ "$tries" -le 0 ] && die "Rustion control plane never came up at $RUSTION_CP"
    sleep 1
done
log "Rustion is up"

#───────────────────────────────────────────────────────────────────
bold "Step 5 — enrol the bastion on BV (KEM pubkey + pinned TLS leaf)"
# Rustion writes its ML-KEM-768 identity (raw 1184 bytes) to identity.pub
# on first start; it is bind-mounted at ./var/rustion. base64 of the raw
# file is exactly the kem_public_key BV expects.
tries=30
until [ -s var/rustion/identity.pub ]; do
    tries=$((tries-1)); [ "$tries" -le 0 ] && die "rustion never wrote var/rustion/identity.pub"
    sleep 1
done
KEM_B64=$(base64 < var/rustion/identity.pub | tr -d '\n')
log "rustion KEM pubkey: $(echo -n "$KEM_B64" | wc -c | tr -d ' ') b64 chars"

# BV also pins rustion's *signing* identity (the Ed25519 + ML-DSA-65
# "webhook" pair) so it can verify rustion's signed responses. Rustion's
# `webhook-key export` emits exactly the shape BV's enrolment consumes:
# SPKI-wrapped Ed25519 + raw ML-DSA-65, both base64.
WH=$("${DC[@]}" exec -T rustion /usr/local/bin/rustion-server \
        control-plane webhook-key export --config /etc/rustion/rustion.toml \
        --format json 2>/dev/null)
ED_SPKI=$(echo "$WH" | jq -r '.ed25519_spki_b64 // empty')
ML_PUB=$(echo "$WH"  | jq -r '.mldsa65_pub_b64 // empty')
[ -n "$ED_SPKI" ] && [ -n "$ML_PUB" ] || die "could not export rustion webhook pubkeys: $WH"
log "rustion signing pubkeys exported (ed25519 SPKI + ml-dsa-65)"

# Pin Rustion's self-signed control-plane leaf so BV's outbound client
# accepts it (BV defaults to strict CA verification when no cert is pinned).
RUSTION_CERT=$(openssl s_client -connect "${RUSTION_CP#https://}" -servername rustion \
    </dev/null 2>/dev/null | openssl x509 -outform pem 2>/dev/null || true)
[ -n "$RUSTION_CERT" ] || warn "could not fetch Rustion TLS leaf — enrolment may fail strict TLS"

ADD=$(jq -n \
    --arg name rustion-e2e --arg endpoint "$RUSTION_ENDPOINT" \
    --arg kem "$KEM_B64" --arg cert "$RUSTION_CERT" \
    --arg ed "$ED_SPKI" --arg ml "$ML_PUB" \
    '{name:$name, endpoint:$endpoint, kem_public_key:$kem,
      public_key_ed25519:$ed, public_key_mldsa65:$ml,
      tls_pinned_cert_pem:$cert, tags:"env=e2e,protocol=ssh",
      description:"e2e docker-compose driver", enabled:true}')
IFS=$'\n' read -r -d '' code body < <(
    api POST /v1/rustion/targets "${RT[@]}" -H 'Content-Type: application/json' -d "$ADD"; printf '\0')
[ "$code" = "200" ] || die "target add failed (HTTP $code): $body"
log "bastion enrolled"

bold "Step 5b — probe bastion until healthy"
# Session-open candidate selection skips any target that isn't `healthy`
# (a freshly-enrolled target sits at `unknown`). An active probe sends a
# signed-nonce health request; rustion's signed reply is verified against
# the signing pubkeys we just enrolled — so this also confirms the
# ed25519/ml-dsa-65 enrolment is correct.
status=""
for _ in $(seq 1 20); do
    api POST /v1/rustion/targets/probe "${RT[@]}" >/dev/null 2>&1 || true
    status=$(curl -sk "$BV_ADDR/v1/rustion/targets/health" "${RT[@]}" \
        | jq -r '(.data.targets // .data // .) | .[0].status // empty' 2>/dev/null)
    case "$status" in up|healthy) break ;; esac
    sleep 1
done
curl -sk "$BV_ADDR/v1/rustion/targets/health" "${RT[@]}" \
    | jq -c '(.data.targets // .data // .) | .[] | {name, status, last_error, latency_ms_p50}' 2>/dev/null || true
case "$status" in
    up|healthy) log "target is $status — eligible for session-open candidate selection" ;;
    *) warn "target never reached a healthy state (status=$status) — session open may fail" ;;
esac

#───────────────────────────────────────────────────────────────────
bold "Step 6 — create resource + ssh-password secret"
api POST "/v1/resources/$RESOURCE" "${RT[@]}" -H 'Content-Type: application/json' \
    -d "{\"name\":\"$RESOURCE\",\"type\":\"server\",\"hostname\":\"target\",\"description\":\"e2e openssh target\"}" \
    >/dev/null
api POST "/v1/resources/secrets/$RESOURCE/$SECRET_KEY" "${RT[@]}" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$TARGET_USER\",\"password\":\"$TARGET_PASS\"}" \
    >/dev/null
log "resource '$RESOURCE' + secret '$SECRET_KEY' written"

#───────────────────────────────────────────────────────────────────
# ssh-through helper: dial Rustion's SSH listener with the ticket as the
# (keyboard-interactive) password and run a probe command on the target.
ssh_through() {
    local ticket=$1 label=$2
    if ! command -v sshpass >/dev/null 2>&1; then
        warn "sshpass not installed — dial manually with the ticket as the password:"
        echo "    SSHPASS='$ticket' sshpass -e ssh -tt -o PreferredAuthentications=password -p $RUSTION_SSH_PORT operator@$RUSTION_SSH_HOST"
        return
    fi
    # Rustion consumes the BV ticket in the SSH *password slot* (auth_password,
    # ticket must look like `tkt_…`), so force the password method — the ssh
    # client renders the bastion's prompt as the ordinary "password:", which
    # `sshpass -e` answers with the ticket. The session then proxies through an
    # *interactive shell* (Rustion's exec_request is a no-op), so we pass no
    # command and drive the shell over stdin; sshpass relays piped input to the
    # PTY after auth. ServerAlive* self-bounds the dial if the proxy wedges, and
    # `${TIMEOUT[@]}` adds a hard wall-clock cap when a timeout(1) is present.
    local out
    out=$(printf 'id -un; hostname; exit\n' | "${TIMEOUT[@]}" \
        env SSHPASS="$ticket" sshpass -e ssh -tt \
            -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o PreferredAuthentications=password -o PubkeyAuthentication=no \
            -o NumberOfPasswordPrompts=1 -o ConnectTimeout=10 \
            -o ServerAliveInterval=5 -o ServerAliveCountMax=3 \
            -p "$RUSTION_SSH_PORT" "operator@$RUSTION_SSH_HOST" 2>&1) || true
    echo "$out" | sed 's/^/[ssh] /'
    if echo "$out" | grep -q "$TARGET_USER"; then
        log "$label: ✅ proxied an SSH shell to the target as '$TARGET_USER'"
    else
        warn "$label: SSH shell output did not confirm the target login (see [ssh] lines)"
    fi
}

#───────────────────────────────────────────────────────────────────
bold "Step 7 — classic session open (root token, raw credential) + SSH through"
OPEN=$(curl -sk "$BV_ADDR/v1/rustion/session/open" "${RT[@]}" -H 'Content-Type: application/json' \
    -d "{\"target_host\":\"target\",\"target_port\":$TARGET_PORT,\"target_protocol\":\"ssh\",
         \"credential_kind\":\"ssh-password\",\"credential_username\":\"$TARGET_USER\",
         \"credential_material\":\"$(printf '%s' "$TARGET_PASS" | base64)\",
         \"ttl_secs\":3600,\"recording\":\"off\"}")
echo "$OPEN" | jq '.data | {session_id, host, port, bastion_name}' 2>/dev/null || echo "$OPEN"
TICKET=$(echo "$OPEN" | jq -r '.data.ticket // empty')
[ -n "$TICKET" ] && ssh_through "$TICKET" "classic" || warn "classic open returned no ticket: $OPEN"

#───────────────────────────────────────────────────────────────────
bold "Step 8 — connect-only path (features/connect-only-access.md)"
log "create connect-only policy + token (connect on the secret, no read)"
POLICY=$(cat <<HCL
path "resources/secrets/$RESOURCE/*" { capabilities = ["connect"] }
path "rustion/*"                     { capabilities = ["create", "update"] }
HCL
)
api POST /v1/sys/policies/acl/connect-only "${RT[@]}" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg p "$POLICY" '{policy:$p}')" >/dev/null
CO_TOKEN=$(curl -sk "$BV_ADDR/v1/auth/token/create" "${RT[@]}" -H 'Content-Type: application/json' \
    -d '{"policies":["connect-only"],"ttl":"1h","display_name":"connect-only-e2e"}' \
    | jq -r '.auth.client_token')
[ -n "$CO_TOKEN" ] && [ "$CO_TOKEN" != null ] || die "connect-only token create failed"
CO=(-H "X-Vault-Token: $CO_TOKEN")
log "connect-only token: $CO_TOKEN"

log "proof A: connect-only token is DENIED a direct read of the secret"
IFS=$'\n' read -r -d '' code body < <(
    api GET "/v1/resources/secrets/$RESOURCE/$SECRET_KEY" "${CO[@]}"; printf '\0')
if [ "$code" = "403" ]; then
    log "  → HTTP 403 (forbidden) as expected — cannot read the credential"
else
    warn "  → expected 403 reading the secret, got HTTP $code: $body"
fi

log "proof B: connect-only token opens a session via rustion/v2/session/open (server-side resolve)"
V2=$(curl -sk "$BV_ADDR/v1/rustion/v2/session/open" "${CO[@]}" -H 'Content-Type: application/json' \
    -d "{\"resource_name\":\"$RESOURCE\",
         \"credential_source\":{\"kind\":\"secret\",\"secret_id\":\"$SECRET_KEY\"},
         \"target_host\":\"target\",\"target_port\":$TARGET_PORT,\"target_protocol\":\"ssh\",
         \"credential_kind\":\"ssh-password\",\"credential_username\":\"$TARGET_USER\",
         \"ttl_secs\":3600,\"recording\":\"off\"}")
echo "$V2" | jq '.data | {session_id, host, port, bastion_name}' 2>/dev/null || echo "$V2"
CO_TICKET=$(echo "$V2" | jq -r '.data.ticket // empty')
[ -n "$CO_TICKET" ] && ssh_through "$CO_TICKET" "connect-only" || warn "v2 open returned no ticket: $V2"

bold "Done — connect-only operator proxied an SSH session without ever reading the credential."

#───────────────────────────────────────────────────────────────────
# Step 9 — multi-instance failover (opt-in: E2E_FAILOVER=1)
#
# Brings up a SECOND Rustion (rustion-2), enrols it, then proves that an
# ordered bastion list fails over to the secondary when the primary is
# killed. This exercises the BastionVault-side dispatcher walk-and-advance
# loop — the chosen alternative to building HA inside Rustion itself.
#───────────────────────────────────────────────────────────────────
if [ -n "$E2E_FAILOVER" ]; then
    bold "Step 9 — multi-instance failover (rustion-2)"

    # 9a. Stand up rustion-2's writable state (mirrors Step 4 for the
    #     primary): own identity/keys, admin user, self-signed TLS leaf.
    mkdir -p var/rustion-2/control-plane var/rustion-2/users var/rustion-2/targets \
             var/rustion-2/roles var/rustion-2/audit var/rustion-2/audit-keys \
             var/rustion-2/recordings
    if [ ! -e var/rustion-2/users/admin.yaml ]; then
        cat > var/rustion-2/users/admin.yaml <<'YAML'
username: admin
enabled: true
roles:
  - admin
allowed_targets: []
mfa: {}
YAML
    fi
    if [ ! -s var/rustion-2/control-plane/tls.crt ]; then
        log "minting self-signed control-plane TLS cert for rustion-2"
        openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
            -keyout var/rustion-2/control-plane/tls.key \
            -out    var/rustion-2/control-plane/tls.crt \
            -subj "/CN=rustion-2" \
            -addext "subjectAltName=DNS:rustion-2,DNS:localhost,IP:127.0.0.1" \
            >/dev/null 2>&1
    fi
    "${DC[@]}" up -d --build rustion-2
    log "waiting for rustion-2 control plane…"
    tries=90
    until curl -ksf "$RUSTION2_CP/v1/health" >/dev/null 2>&1; do
        tries=$((tries-1)); [ "$tries" -le 0 ] && die "rustion-2 control plane never came up at $RUSTION2_CP"
        sleep 1
    done
    log "rustion-2 is up"

    # 9b. Enrol rustion-2 as a second BV target (mirrors Step 5).
    tries=30
    until [ -s var/rustion-2/identity.pub ]; do
        tries=$((tries-1)); [ "$tries" -le 0 ] && die "rustion-2 never wrote identity.pub"
        sleep 1
    done
    KEM2_B64=$(base64 < var/rustion-2/identity.pub | tr -d '\n')
    WH2=$("${DC[@]}" exec -T rustion-2 /usr/local/bin/rustion-server \
            control-plane webhook-key export --config /etc/rustion/rustion.toml \
            --format json 2>/dev/null)
    ED2_SPKI=$(echo "$WH2" | jq -r '.ed25519_spki_b64 // empty')
    ML2_PUB=$(echo "$WH2"  | jq -r '.mldsa65_pub_b64 // empty')
    [ -n "$ED2_SPKI" ] && [ -n "$ML2_PUB" ] || die "could not export rustion-2 webhook pubkeys: $WH2"
    RUSTION2_CERT=$(openssl s_client -connect "${RUSTION2_CP#https://}" -servername rustion-2 \
        </dev/null 2>/dev/null | openssl x509 -outform pem 2>/dev/null || true)
    ADD2=$(jq -n \
        --arg name rustion-e2e-2 --arg endpoint "$RUSTION2_ENDPOINT" \
        --arg kem "$KEM2_B64" --arg cert "$RUSTION2_CERT" \
        --arg ed "$ED2_SPKI" --arg ml "$ML2_PUB" \
        '{name:$name, endpoint:$endpoint, kem_public_key:$kem,
          public_key_ed25519:$ed, public_key_mldsa65:$ml,
          tls_pinned_cert_pem:$cert, tags:"env=e2e,role=dr",
          description:"e2e failover secondary", enabled:true}')
    IFS=$'\n' read -r -d '' code body < <(
        api POST /v1/rustion/targets "${RT[@]}" -H 'Content-Type: application/json' -d "$ADD2"; printf '\0')
    [ "$code" = "200" ] || die "rustion-2 target add failed (HTTP $code): $body"
    log "rustion-2 enrolled"

    # 9c. Probe both targets healthy.
    for _ in $(seq 1 20); do
        api POST /v1/rustion/targets/probe "${RT[@]}" >/dev/null 2>&1 || true
        sleep 1
        HEALTH=$(curl -sk "$BV_ADDR/v1/rustion/targets/health" "${RT[@]}")
        ups=$(echo "$HEALTH" | jq -r '[(.data.targets // .data // .)[] | select(.status=="up" or .status=="healthy")] | length' 2>/dev/null)
        [ "${ups:-0}" -ge 2 ] && break
    done
    log "healthy targets: ${ups:-0}"

    # Resolve the two target ids by name.
    TARGETS=$(curl -sk "$BV_ADDR/v1/rustion/targets" "${RT[@]}")
    ID1=$(echo "$TARGETS" | jq -r '(.data.targets // .data // .)[] | select(.name=="rustion-e2e") | .id' | head -1)
    ID2=$(echo "$TARGETS" | jq -r '(.data.targets // .data // .)[] | select(.name=="rustion-e2e-2") | .id' | head -1)
    [ -n "$ID1" ] && [ -n "$ID2" ] || die "could not resolve both target ids (id1=$ID1 id2=$ID2)"
    log "primary=$ID1  secondary=$ID2"

    # 9d. Create an ordered bastion group [primary, secondary] — exercises
    #     group CRUD + the dispatcher's group path.
    GRP=$(jq -n --arg n e2e-failover --arg a "$ID1" --arg b "$ID2" \
        '{name:$n, members:[$a,$b], selection:"ordered", description:"e2e ordered failover"}')
    api POST /v1/rustion/bastion-groups "${RT[@]}" -H 'Content-Type: application/json' -d "$GRP" >/dev/null
    log "bastion group 'e2e-failover' = [primary → secondary] (ordered)"

    open_on() {  # echoes the landed bastion_name for an ordered [id1,id2] open
        curl -sk "$BV_ADDR/v1/rustion/session/open" "${RT[@]}" -H 'Content-Type: application/json' \
            -d "{\"target_host\":\"target\",\"target_port\":$TARGET_PORT,\"target_protocol\":\"ssh\",
                 \"credential_kind\":\"ssh-password\",\"credential_username\":\"$TARGET_USER\",
                 \"credential_material\":\"$(printf '%s' "$TARGET_PASS" | base64)\",
                 \"ttl_secs\":600,\"recording\":\"off\",
                 \"bastions\":[\"$ID1\",\"$ID2\"]}"
    }

    # 9e. Open #1 — both up, ordered list → lands on the primary.
    OPEN1=$(open_on)
    LANDED1=$(echo "$OPEN1" | jq -r '.data.bastion_name // empty')
    log "open #1 landed on: ${LANDED1:-<none>}"
    if [ "$LANDED1" = "rustion-e2e" ]; then
        log "  → ✅ ordered list picked the primary first"
    else
        warn "  → expected primary 'rustion-e2e', got '${LANDED1:-<none>}': $OPEN1"
    fi

    # 9f. Kill the primary, then re-probe so its health flips off `up`.
    bold "Step 9g — kill the primary and re-open"
    "${DC[@]}" stop rustion >/dev/null 2>&1 || true
    log "primary stopped; re-probing…"
    for _ in $(seq 1 10); do
        api POST /v1/rustion/targets/probe "${RT[@]}" >/dev/null 2>&1 || true
        sleep 1
    done

    # 9h. Open #2 — primary unreachable; the walk-and-advance loop (or the
    #     health filter) falls through to the secondary.
    OPEN2=$(open_on)
    LANDED2=$(echo "$OPEN2" | jq -r '.data.bastion_name // empty')
    TRIED=$(echo "$OPEN2" | jq -rc '.data.bastion_candidates_tried // []')
    log "open #2 landed on: ${LANDED2:-<none>}  (candidates_tried=$TRIED)"
    if [ "$LANDED2" = "rustion-e2e-2" ]; then
        bold "✅ FAILOVER PROVEN — primary down, session opened on the secondary."
    else
        warn "❌ expected failover to 'rustion-e2e-2', got '${LANDED2:-<none>}': $OPEN2"
    fi

    # 9i. The killed primary is excluded from the random pool too.
    POOL=$(curl -sk "$BV_ADDR/v1/rustion/session/open" "${RT[@]}" -H 'Content-Type: application/json' \
        -d "{\"target_host\":\"target\",\"target_port\":$TARGET_PORT,\"target_protocol\":\"ssh\",
             \"credential_kind\":\"ssh-password\",\"credential_username\":\"$TARGET_USER\",
             \"credential_material\":\"$(printf '%s' "$TARGET_PASS" | base64)\",
             \"ttl_secs\":600,\"recording\":\"off\"}")
    POOL_LANDED=$(echo "$POOL" | jq -r '.data.bastion_name // empty')
    if [ "$POOL_LANDED" = "rustion-e2e-2" ]; then
        log "random-pool open also landed on the only healthy target (secondary) ✅"
    else
        warn "random-pool open landed on '${POOL_LANDED:-<none>}' (expected secondary)"
    fi
fi

bold "Explore with: ${DC[*]} logs -f   |   tear down with: ${DC[*]} down -v"
