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
- `bvault` CLI built (`cargo build --release --bin bvault` in the repo root)
- `rustion` binary from the Rustion sibling repo built into `/usr/local/bin`
  inside the rustion container (see `Dockerfile.rustion` once it lands —
  not part of this scaffold)

## Driver

`run.sh` brings up the stack, enrols the Rustion target on BV, calls
`bvault rustion target health` to confirm the bastion is reachable,
then walks an SSH session through the full pipeline (steps 1 → 6 in
the diagram).

Today the script stops after step 4 with a clear log line — the
full bytes-proxy via the SSH listener is wired in `rustion-ssh::server`
but exercising it end-to-end through a real Docker network needs a
`Dockerfile.bastionvault` and `Dockerfile.rustion` that aren't yet in
either repo. The compose file is structured so adding those two
Dockerfiles is a one-line `build:` change per service.

## Layout

```
tests/e2e/rustion-ssh/
  README.md                 — this file
  docker-compose.yaml       — three-service stack
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
