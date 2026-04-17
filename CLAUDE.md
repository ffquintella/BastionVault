# CLAUDE.md

This file is read by Claude Code on every session start. It provides project context and references to detailed instructions.

See `agent.md` and follow the instructions there. 

## Project

BastionVault is a Rust-based secrets management server compatible with HashiCorp Vault's API. It provides identity-based access control, encrypted storage, post-quantum cryptography, and a Tauri desktop GUI.

## Key Files

| File | Purpose |
|------|---------|
| `agent.md` | **Full agent instructions** -- security standards, code organization, change discipline, testing, changelog and tracking requirements. Read this first. |
| `roadmap.md` | Global feature status table and initiative tracker. Update after every phase/feature. |
| `CHANGELOG.md` | Changelog with maintenance instructions in the HTML comment block. Update after every feature, phase, or roadmap stage. |
| `features/*.md` | Feature specifications with implementation status. Update "Current State" as work progresses. |
| `roadmaps/*.md` | Multi-phase roadmap docs. Update phase status as work is done. |

## Tracking Rules

After completing any feature, phase, or roadmap stage:

1. **Update `CHANGELOG.md`** -- add entries under `[Unreleased]` in the correct category (Added/Changed/Fixed/Removed).
2. **Update `roadmap.md`** -- change the feature status (Todo → In Progress → Done), move completed initiatives.
3. **Update the relevant feature file** (`features/*.md`) -- mark phases Done, update "Current State".
4. **Update the relevant roadmap file** (`roadmaps/*.md`) -- mark phases Complete if applicable.



## Build Commands

```bash
# Rust
cargo check                        # Quick compile check
cargo check --workspace            # Full workspace (includes GUI)
cargo test --lib                   # Run library tests
cargo clippy --lib                 # Lint

# GUI (from gui/ directory)
cd gui && npm install              # Install frontend deps
npx tsc --noEmit                   # TypeScript check
npx vite build                     # Build frontend
npx vitest run                     # Run UI tests (42 tests)
cargo check -p bastion-vault-gui   # Check Tauri backend

# HA tests (requires free ports)
CARGO_TEST_HIQLITE=1 cargo test --test hiqlite_ha_fault_injection
```

## GUI Development Rules

- **All pages must be responsive** — never use `max-w-*` classes on the main page container. Pages must fill the available width within the Layout sidebar. Use responsive grid classes (`grid-cols-1 sm:grid-cols-2 lg:grid-cols-3`) for card layouts.
- **Use `min-w-0` and `truncate`** on text that could overflow (URLs, hostnames, long names).
- **Modals** use `size="sm" | "md" | "lg"` from the Modal component — these are the only places where max-width is appropriate.
- **Forms** should use `grid grid-cols-2 gap-3` for field pairs, with `col-span-2` for full-width fields (tags, notes, textareas).

## Architecture Overview

- **Storage**: File, MySQL, Hiqlite (default, embedded Raft SQLite with HA)
- **Crypto**: ChaCha20-Poly1305 barrier, ML-KEM-768 + ML-DSA-65 post-quantum
- **Auth backends**: Token, UserPass, AppRole, Certificate, FIDO2/WebAuthn
- **GUI**: Tauri v2 + React 19 + TypeScript + Tailwind CSS 4, embedded vault mode
- **Backup**: BVBK binary format with HMAC-SHA256 integrity
