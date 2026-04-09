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
- Do not refactor unrelated code while implementing a security or correctness change.
- Preserve existing interfaces unless there is a strong reason to change them.
- If a migration is needed, use versioned formats and compatibility paths.
- For storage or encryption format changes, support read-old/write-new migrations unless explicitly directed otherwise.

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

## What To Avoid

- speculative rewrites
- unnecessary dependency churn
- custom crypto
- silent downgrade paths
- insecure defaults for development convenience
- mixing unrelated cleanup into security-sensitive changes

## Expected Output From Agents

- explain assumptions clearly
- call out security-sensitive tradeoffs
- identify migration risks before changing persisted formats
- verify behavior with tests where possible
- leave the codebase more explicit and more defensible than it was before

