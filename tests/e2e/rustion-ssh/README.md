# Rustion-mediated SSH — end-to-end demo

This directory ships a docker-compose harness that exercises the full
Phase 3.1 pipeline:

```
operator-shell
      │
      │ 1. POST /v1/rustion/session/open
      ▼
┌──────────────┐  2. BVRG-v1 envelope (sign+encrypt)  ┌──────────────┐
│ BastionVault │ ───────────────────────────────────▶ │   Rustion    │
│              │  3. {session_id, host, port, ticket} │ control plane│
│              │ ◀─────────────────────────────────── │              │
└──────────────┘                                      └──────────────┘
                                                             │
       ┌─────────────────────────────────────────────────────┘
       │  4. ssh -p <bastion-port> <username>@bastion
       │     password = ticket
       ▼
   ┌──────────────┐  5. Rustion verifies ticket → opens
   │   Rustion    │     proxy to target with decrypted
   │   ssh proxy  │     credential
   └──────────────┘
       │
       │ 6. ssh -p 22 deploy@openssh-target
       ▼
   ┌──────────────┐
   │ OpenSSH      │
   │ target       │
   └──────────────┘
```

## Requirements

- Docker + docker-compose v2
- The BV repo at `/Users/felipe/Dev/BastionVault` (or wherever you cloned it)
- The Rustion repo as a sibling of the BastionVault repo (the compose file
  references `../../../../rustion` — i.e. `/Users/felipe/Dev/rustion` next to
  `/Users/felipe/Dev/BastionVault` — as the build context for the rustion
  service)
- Host tools used by `run.sh`: `curl`, `jq`, `openssl`, `ssh`, and
  `sshpass` (the last is optional — without it the driver prints the
  manual `ssh` command instead of dialling through automatically).

`run.sh` drives the server entirely over its HTTP API; the `bvault` CLI
is **not** required on the host.

## Driver

`run.sh` is self-contained — `./run.sh` from cold start:

1. brings up `bastion-vault`, then **init + unseals it over the API**
   (the server starts sealed/uninitialised; there is no auto-init env
   var) and captures the root token;
2. issues + exports BV's master signing pubkey and writes the Rustion
   **authority record** in the schema rustion deserialises
   (`pubkey_ed25519_b64` / `pubkey_mldsa65_b64` = base64 of the raw key
   bytes, *not* PEM);
3. brings up `rustion` + `openssh-target`, then enrols the bastion on BV
   using rustion's ML-KEM-768 pubkey (read from the bind-mounted
   `var/rustion/identity.pub`) and pins rustion's self-signed TLS leaf
   (BV uses strict CA verification unless a leaf is pinned);
4. creates a resource + ssh-password secret and walks a **classic**
   session (root token, raw credential) through to a shell on the
   target;
5. exercises the **connect-only** path
   (`features/connect-only-access.md`): a connect-only token is denied a
   direct read of the secret (HTTP 403) yet its
   `rustion/v2/session/open` resolves the credential server-side and
   proxies an SSH session through the bastion — the operator never reads
   the credential.

Both images are multi-stage builds (rust:1.82-bookworm builder +
distroless cc-debian12 runtime) shipping just the `bvault` /
`rustion-server` binaries. The compose file builds them on first `up`;
subsequent runs reuse the cached layers.

To reuse an already-initialised `var/bv`, pass `BV_ROOT_TOKEN=…`. To
start fresh, `docker compose down -v && rm -rf var/bv/* var/rustion/*`.

### Multi-instance failover (`E2E_FAILOVER=1`)

`E2E_FAILOVER=1 ./run.sh` loads the `docker-compose.failover.yaml`
overlay (a second bastion, `rustion-2`) and appends **Step 9**, which
proves BastionVault-side failover — the alternative to building HA
inside Rustion:

6. enrols `rustion-2` as a second target, creates an ordered bastion
   group `[primary → secondary]`, and opens a session with an ordered
   bastion list → it lands on the **primary**;
7. **stops the primary**, re-probes, and re-opens → the dispatcher's
   walk-and-advance loop falls through to the **secondary**, and a
   random-pool open likewise excludes the dead primary.

## Layout

```
tests/e2e/rustion-ssh/
  README.md                 — this file
  docker-compose.yaml       — three-service stack
  docker-compose.failover.yaml — overlay adding rustion-2 (E2E_FAILOVER)
  run.sh                    — driver script
  config/
    bv-policy.hcl           — minimal admin policy for the test operator
    rustion.toml            — Rustion config with control-plane listener
    rustion-authorities/    — BV master pubkey pinned here
    openssh-target/         — sshd_config + an authorized_keys file
```

## Known gaps

- BV master signing-key is the Phase 2 ephemeral stub. Phase 9 swaps
  this for a PKI-issued cert; the e2e flow uses whatever the running
  BV instance has stashed at `rustion/master/signing-key`.
- The Rustion authority record's deployment_id binding (Phase 9) is
  not enforced yet — the e2e accepts any envelope signed by the
  pinned pubkey.
- ssh-key / ssh-cert credential kinds aren't wired in the proxy loop
  yet (only ssh-password), so the demo uses a password credential.
