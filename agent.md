# Agent Instructions

This repository handles security-sensitive code. Treat correctness, reviewability, and operational safety as first-order requirements.

## Core Standards

- Prefer simple, explicit designs over clever abstractions.
- Optimize for maintainability and auditability, not novelty.
- Preserve backwards compatibility unless a breaking change is explicitly intended and documented.
- Do not introduce hidden behavior, implicit fallbacks, or silent recovery for security-critical paths.
- Make failure modes explicit, deterministic, and observable.

## Security Expectations

- Default to secure-by-default behavior.
- Minimize the trusted computing base when adding dependencies or new code paths.
- Avoid unsafe code unless it is strictly necessary and justified in comments and review notes.
- Avoid introducing cryptographic code ad hoc. Use vetted libraries and narrow interfaces.
- Never invent or modify cryptographic schemes informally.
- Separate key establishment, key wrapping, and payload encryption responsibilities clearly.
- Treat authentication, authorization, key management, storage barriers, TLS, PKI, and secret handling as high-risk areas.
- Do not log secrets, keys, tokens, plaintext sensitive material, or raw credential artifacts.
- Zeroize sensitive material where practical and avoid unnecessary copies.
- Prefer constant-time or side-channel-aware primitives from maintained libraries rather than custom logic.

## Change Discipline

- Keep changes small, scoped, and easy to review.
- Prefer small code chunks over large rewrites.
- Do not refactor unrelated code while implementing a security or correctness change.
- Preserve existing interfaces unless there is a strong reason to change them.
- If a migration is needed, use versioned formats and compatibility paths.
- For storage or encryption format changes, support read-old/write-new migrations unless explicitly directed otherwise.

## Code Organization

- Prefer smaller modules with clear ownership boundaries.
- When a subsystem grows beyond a single file or becomes reusable, split it into smaller modules before adding more behavior.
- Favor incremental extraction into a `crates/` directory when isolating major capabilities such as crypto providers, storage formats, protocol layers, or migration tooling.
- New crates should have narrow responsibilities, explicit public APIs, and minimal dependency surfaces.
- Avoid creating large god-modules that mix parsing, crypto, I/O, persistence, and orchestration logic.
- If a change touches a large file repeatedly, consider a preparatory split before implementing new behavior.

## HTTP API Routes

- **All new HTTP routes must be introduced under the `v2/` prefix.** This
  is the project's forward-going API version. Example: a new identity
  endpoint is `v2/identity/group/user/{name}`, not `identity/group/...`
  and not `v1/...`.
- Do **not** add new routes or new operations (Read/Write/List/Delete) to
  existing `v1/` paths. `v1` is frozen for Vault compatibility and
  accepts only bug fixes and security patches.
- When extending an existing subsystem, mirror the route under `v2/` and
  implement the new behavior there. The `v1` handler may delegate to the
  `v2` implementation, but never the other way around.
- Tauri commands, internal logical-backend paths, and tests that target
  new functionality must use the `v2/` form. Update `docs/docs/api.md`
  and the relevant `features/*.md` file with the `v2` path.
- Breaking changes to request or response shape are allowed on `v2`
  routes only up until the first stable release that ships them; after
  that, treat them the same as `v1`.

## Dependency Rules

- Prefer maintained, widely reviewed libraries with clear ownership and active releases.
- Do not add dependencies casually, especially for crypto, parsing, serialization, TLS, or authentication.
- When adding a dependency, document why it is needed and why existing code or dependencies are insufficient.
- Prefer Rust-native libraries when they materially reduce complexity or external runtime dependencies.

## Code Quality

- Write code that is easy to reason about under incident conditions.
- Use descriptive names and explicit control flow.
- Add comments only where they clarify non-obvious security or operational intent.
- Avoid broad catch-all error handling.
- Bubble up meaningful errors with enough context for operators and reviewers.
- Do not suppress warnings without a concrete reason.

## Testing Requirements

- Add or update tests for every non-trivial behavior change.
- Prefer deterministic tests with clear inputs and expected outputs.
- For crypto or storage changes, include compatibility tests and malformed-input tests.
- For security fixes, add regression coverage that proves the previous behavior cannot silently return.
- Do not claim a migration is complete without verifying old data, old config, or old API paths where relevant.

## Review Priorities

When making or reviewing changes, prioritize:

1. secret leakage risk
2. authentication and authorization correctness
3. cryptographic correctness and misuse resistance
4. compatibility and migration safety
5. operational debuggability
6. performance only after the above are satisfied

## Operational Safety

- Assume upgrades may happen on live systems with old data.
- Avoid one-way changes to persisted formats unless explicitly planned.
- Prefer feature flags, staged rollouts, and format versioning for risky migrations.
- Keep observability intact for security-relevant failures.

## Local Tauri MCP Bridge

- The `hypothesi/mcp-server-tauri` bridge is approved only for local GUI
  development and inspection. It must stay behind the GUI crate's
  `mcp_local_dev` Cargo feature and a `BASTION_TAURI_MCP=1` runtime opt-in.
- The bridge must bind only to `127.0.0.1`. Do not switch it to `0.0.0.0`
  or expose it over a remote interface without a separate security review.
- Do not enable the bridge in release, production, CI packaging, or builds
  that handle real operator secrets. Use disposable local development data.
- `make run-dev-gui` is the intended local entry point; it enables the
  feature and runtime flag for the embedded file-storage development GUI.
- Treat MCP screenshots, DOM snapshots, IPC events, backend state, and logs
  as sensitive. Do not paste or persist them unless they have been reviewed
  for secret material.

## What To Avoid

- speculative rewrites
- large monolithic patches when smaller sequenced changes would work
- unnecessary dependency churn
- custom crypto
- silent downgrade paths
- insecure defaults for development convenience
- mixing unrelated cleanup into security-sensitive changes

## Changelog and Tracking

### CHANGELOG.md

- Keep `CHANGELOG.md` updated after **every feature, phase, or roadmap stage**.
- Use [Keep a Changelog](https://keepachangelog.com/) format with sections: Added, Changed, Deprecated, Removed, Fixed, Security.
- Group entries under the `[Unreleased]` heading until a version is cut.
- Every commit or PR that modifies behavior, adds features, removes features, fixes bugs, or changes dependencies must have a corresponding changelog entry.
- Write entries from the operator's perspective: what changed and why it matters, not implementation details.
- Use imperative mood ("Add X", not "Added X" or "Adds X").
- Group related entries under a sub-heading (e.g., `#### FIDO2 Auth Backend`).
- Reference the feature file or roadmap phase (e.g., `(Phase 5, features/import-export-backup-restore.md)`).
- See the HTML comment block at the top of `CHANGELOG.md` for the full maintenance guide.

### roadmap.md

- Update `roadmap.md` whenever a feature status changes (Todo → In Progress → Done).
- Move completed initiatives from "Active Initiatives" to "Completed Initiatives".
- Keep the feature status table accurate -- it is the single source of truth for project progress.

### Feature Files (features/*.md)

- Update the "Current State" section in each feature file when implementation progresses.
- Mark phase tables (Done/Pending) to reflect actual file-level completion.
- Create a new feature file for any significant new capability before implementation begins.

### Roadmap Files (roadmaps/*.md)

- Update phase status (Complete/Pending) as work is done.
- Keep the "What Is Not Yet Implemented" section accurate.
- When all phases are complete, update the "Current State" header to reflect completion.

## Expected Output From Agents

- explain assumptions clearly
- call out security-sensitive tradeoffs
- identify migration risks before changing persisted formats
- verify behavior with tests where possible
- leave the codebase more explicit and more defensible than it was before
