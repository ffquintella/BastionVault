# BastionVault Roadmap

This document is the global entrypoint for roadmap and long-term planning documents in this repository.

The post-quantum migration is active and already partially implemented in the codebase. The detailed roadmap below tracks both the target state and the migration status of each phase.

## Roadmap Index

- [Post-Quantum Crypto Migration](/Users/felipe/Dev/BastionVault/roadmaps/post-quantum-crypto-migration.md)
  Active roadmap for removing Tongsuo, reducing OpenSSL coupling, adopting `ChaCha20-Poly1305` for payload encryption, and introducing `ML-KEM-768` plus `ML-DSA-65` for post-quantum key management.
- [Post-Quantum Crypto Progress](/Users/felipe/Dev/BastionVault/roadmaps/post-quantum-crypto-progress.md)
  Execution tracker for completed slices, in-flight work, immediate next steps, and recent verification coverage.

## Notes

- Put new roadmap documents under [roadmaps](/Users/felipe/Dev/BastionVault/roadmaps).
- Keep this file updated whenever a roadmap is added, renamed, or removed.
- Prefer one roadmap per major initiative so planning, sequencing, and acceptance criteria stay reviewable.
