# Roadmap: Graphical Policy Builder & Validator

Feature spec: [`features/policy-builder-validator.md`](../features/policy-builder-validator.md).

Adds a visual, block-based policy construction surface and an effectivity validator beside the existing textual HCL editor on the [Policies page](../gui/src/routes/PoliciesPage.tsx). The textual editor is preserved; everything here is additive. HCL remains the source of truth — the builder serializes to and parses from it.

## Goals

- Let operators construct ACL policies without hand-writing HCL, with live linting and dynamic optional blocks.
- Prove what a draft policy grants — `(path, capability)` → allow/deny + matched rule — **before** it is saved and applied to live tokens.
- Attach savable test cases to a policy as documentation of intent and as a regression gate on every edit.
- Add zero risk of drift between the simulator and production authorization by making the authoritative verdict come from the real ACL matcher (hybrid engine).

## Status

| Phase | Title | Status |
|---|---|---|
| 1 | Backend dry-run endpoint | `[ ]` Todo |
| 2 | Client lint + simulator (TS) | `[ ]` Todo |
| 3 | Visual builder tab | `[ ]` Todo |
| 4 | Validate & test tab + test-case persistence | `[ ]` Todo |
| 5 | Polish, tests & docs | `[ ]` Todo |

## Sequencing rationale

Phase 1 lands first because it is the authoritative engine and can be validated end-to-end against existing policies with no UI beyond a throwaway test panel — it de-risks the whole feature before any builder UI exists. Phase 2 (client lint) is independent and gives instant feedback. Phases 3 and 4 are the two user-facing tabs; the builder (3) and the validator (4) can proceed in parallel once 1+2 exist. Phase 5 closes out tracking, tests, and docs per `CLAUDE.md`.

## Phase 1 — Backend dry-run endpoint

**Deliverable:** a stateless evaluation endpoint that never persists.

- `POST /v1/sys/policies/acl/test` — body `{ policy, cases[] }`, response `{ parse_ok, errors[], results[] }` where each result carries `allowed`, `matched_path`, `match_kind` (`exact | prefix | segment_wildcard | none`), and `denied_by_deny`.
- Reuses `PolicyConfig::parse` and the `ACL` builder + matcher in [`src/modules/policy/`](../src/modules/policy/); no new evaluation logic.
- Requires the same capability as policy write on `sys/policies/acl/*`.
- Tauri command `policy_test` in [`gui/src-tauri/src/commands/policies.rs`](../gui/src-tauri/src/commands/policies.rs) + TS wrapper in [`gui/src/lib/api.ts`](../gui/src/lib/api.ts).

**Acceptance:** Rust tests cover parse-error reporting, every `match_kind`, `deny` precedence, group/scope-gated cases, the `+*` rejection, and a guarantee that no storage write occurs. The command returns a correct verdict for the `administrator`, `default`, and `totp-admin` built-ins.

## Phase 2 — Client lint + simulator (TypeScript)

**Deliverable:** instant, non-authoritative feedback while typing.

- TS module: HCL tokenizer → block model; capability-name whitelist; glob lint (`+*`, empty capability list, broad `*`); TTL format check.
- Lightweight TS path matcher encoding the exact > prefix > segment precedence for a preview allow/deny, clearly labelled non-authoritative.

**Acceptance:** `vitest` round-trip stability over a corpus of real policies; lint catches each documented error class; preview agrees with the Phase 1 backend on the parity spot-check corpus.

## Phase 3 — Visual builder tab

**Deliverable:** `PolicyBlockEditor` as a third tab on the policy detail panel.

- Path rule = `Card` with path `Input` + glob lint badge, capability toggle chips (`deny` greys the rest; `sudo` warned; `connect` hinted), drag-reorder.
- Collapsible dynamic blocks: required/allowed/denied parameters, `min/max_wrapping_ttl`, `groups`, `scopes`.
- Live HCL preview pane. HCL ⇄ blocks round-trip; on parse failure, keep the operator on the source tab with the error shown.

**Acceptance:** building a policy in the UI and switching to the source tab yields HCL that parses server-side; editing HCL and switching back reconstructs equivalent blocks.

## Phase 4 — Validate & test tab + test-case persistence

**Deliverable:** `PolicyValidatorPanel` + saved test cases.

- Lint/parse results list (errors + warnings) over the draft.
- Editable `(path, capability, expect)` rows; "Run" shows the authoritative verdict + matched rule from the Phase 1 endpoint.
- Persistence under `policy-tests/<name>` via `read_policy_tests` / `write_policy_tests` commands (`GET/PUT /v1/sys/policies/acl/<name>/tests`).
- Save-time regression gate: failing saved cases block save with an explicit "save anyway" override; "N / M cases pass" shown by the Save button.

**Acceptance:** a regressive edit that breaks a saved case is blocked (with override); test cases survive policy edits and are shown on reload.

## Phase 5 — Polish, tests & docs

- Integrate with `PolicyHistoryPanel` (test cases unaffected by restore semantics, or restored alongside — decide and document).
- Full `vitest` coverage for the TS parser/simulator; Rust tests for the dry-run + tests endpoints.
- Operator docs under `docs/`.
- Tracking updates per [`CLAUDE.md`](../CLAUDE.md): `CHANGELOG.md`, `roadmap.md`, this file, and `features/policy-builder-validator.md`.

## Open questions

- Whether restoring a historical policy version should also restore its test cases of that era, or keep current test cases. Leaning toward keeping current cases (they encode present intent) and surfacing a warning when a restore makes them fail.
- Optional Monaco/CodeMirror syntax highlighting for the source tab — deferred; not required for any phase.
