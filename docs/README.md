# BastionVault

A Rust-based secrets management server compatible with HashiCorp Vault's API, with **post-quantum cryptography** (ML-KEM-768 + ML-DSA-65), an embedded **Tauri desktop GUI**, and a **Hiqlite** HA storage backend.

> Looking for the source? [github.com/ffquintella/BastionVault](https://github.com/ffquintella/BastionVault)

## Start here

- [Quick start](quick-start.md) — boot a vault, init, unseal, write your first secret.
- [Install](install.md) — build from source, package, or Podman.
- [Configuration](configuration.md) — storage + listener + cluster config in HCL.
- [Authentication](authentication.md) — Token, UserPass, AppRole, Certificate, FIDO2, OIDC.

## Operate

- [Administration](administration.md) — seal/unseal, mounts, policies, identity groups, sharing.
- [API reference](api.md) — every HTTP route the server exposes.
- [Cluster + client discovery](cluster-client-discovery.md) — SRV records and `/sys/health` scoring.
- [CLI reference](cli-reference.md) — every `bvault` subcommand.

## Architecture

- [Design](design.md) — Core / Modules / Interface decomposition with diagram.
- [Security structure](security-structure.md) — barrier, KEK rotation, FIDO2 attestation handling.
- [Cryptography](crypto.md) — ML-KEM-768 + ML-DSA-65, ChaCha20-Poly1305 barrier.
- [Requirements](req.md) — the original spec the implementation targets.

## Storage backends

- [Overview](backend/database/overview.md)
- [MySQL](backend/database/mysql/mysql.md) — opt-in legacy backend (`--features storage_mysql`)

---

> This site is rendered with [Docsify](https://docsify.js.org/) — no build step. Edit the `.md` files under [`docs/`](https://github.com/ffquintella/BastionVault/tree/main/docs) and reload; sidebar lives in [`docs/_sidebar.md`](_sidebar.md).
