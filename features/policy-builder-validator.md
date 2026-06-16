# Feature: Graphical Policy Builder & Validator

## Summary

Add two tightly-related capabilities to the GUI's [Policies page](../gui/src/routes/PoliciesPage.tsx), sitting **beside** the existing textual HCL editor — never replacing it:

1. **Visual builder** — a block-based, form-driven editor where each `path "..." { ... }` rule is a draggable card with capability toggles, glob linting, and collapsible dynamic blocks (parameters, TTL bounds, asset-group / ownership-scope filters). The builder round-trips losslessly to and from HCL, so an operator can move between the visual and source views freely.
2. **Validate & test** — a panel that (a) lints and parses the draft policy, surfacing syntax and semantic errors inline, and (b) runs **effectivity test cases**: `(path, capability)` assertions evaluated against the draft policy, reporting allow/deny **and the rule that matched**. Saved test cases double as regression checks gating every save.

The two are complementary: the builder reduces the chance of writing a bad policy; the validator proves what a policy actually grants before it is applied to live tokens.

## Motivation

- **Policies are the highest-blast-radius object in the vault.** A stray `*` prefix or a forgotten `deny` silently over- or under-grants every token mapped to the policy. Today the only authoring surface is a raw `<textarea>` with no syntax highlighting, no linting, and no way to see what a rule grants without saving it and minting a test token.
- **The path-matching precedence is non-obvious.** Exact rules beat prefix (`*`) rules beat segment-wildcard (`+`) rules, `deny` always wins on merge, and asset-group / ownership-scope filters (`groups`, `scopes`) further gate a match. Operators routinely guess wrong about which rule applies to a given path. An effectivity simulator that names the matched rule turns this from tribal knowledge into a visible answer.
- **No safe dry-run exists.** `POST /v2/sys/capabilities-self` only evaluates the *caller's live token*, not an arbitrary draft. There is no way to ask "if I saved this text, what would it grant?" without actually saving it.
- **Reviewability.** Saved test cases attached to a policy document operator intent ("the SRE group may read but never delete team DB creds") and catch regressions when the policy is later edited.

## Current State

- **Not started.** This spec and the companion [roadmap](../roadmaps/policy-builder-validator.md) are drafted; no code yet.
- The existing Policies page already provides the foundation this builds on: Editor / History tabs, a plain `<textarea>` HCL editor with dirty-state tracking, a Create modal, [`PolicyHistoryPanel`](../gui/src/components/PolicyHistoryPanel.tsx) with before/after diffs + restore, and full CRUD wired through the Tauri commands `list_policies` / `read_policy` / `write_policy` / `delete_policy` / `list_policy_history` ([`gui/src-tauri/src/commands/policies.rs`](../gui/src-tauri/src/commands/policies.rs)).
- The backend HCL parser and ACL evaluator already model everything the builder and simulator need: the 10 capabilities, `+`/`*` wildcards, parameter and TTL constraints, and asset-group / ownership-scope filters ([`src/modules/policy/policy.rs`](../src/modules/policy/policy.rs), [`acl.rs`](../src/modules/policy/acl.rs)).

## Design

### Capability model (authoritative, from `policy.rs`)

The builder's capability toggles map 1:1 to the backend `Capability` bitmask:

| Capability | Notes for the UI |
|---|---|
| `deny` | Mutually-exclusive styling: when on, all other caps on the block are greyed and ignored (mirrors the backend rule that `deny` drops every other capability and always wins on merge). |
| `create`, `read`, `update`, `delete`, `list` | The standard CRUD set; offered as the default chip group. |
| `patch` | Advanced; partial update. |
| `sudo` | Flagged with a warning affordance — root-equivalent on the matched path. |
| `connect` | Bastion/proxy session capability (independent of `read`); shown with a one-line hint that it grants session access without exposing the credential. |
| `root` | Surfaced read-only/disabled in the per-path editor; root is a policy-level concept, not a per-path grant in normal authoring. |

### Path-matching precedence (drives the simulator's "matched rule" output)

The simulator and the lint both encode the ACL's evaluation order:

1. **Exact** rules (no wildcard) — highest precedence.
2. **Prefix** rules (trailing `*`) — longest matching prefix wins.
3. **Segment-wildcard** rules (`+` matches exactly one path segment).
4. **Group-gated** (`groups = [...]`) and **scope-filtered** (`scopes = [...]`) rules are evaluated as additional gates at authorize time, not merged into the base trie.
5. `deny` on any matching rule overrides all granted capabilities.

The illegal `+*` combination (a segment wildcard immediately followed by a prefix wildcard) is rejected by the parser and must be caught by the client lint before save.

### Hybrid evaluation engine

The effectivity verdict uses a **hybrid** approach (decided during design review):

- **Client-side TypeScript** provides instant feedback while typing — tokenize HCL into the block model, validate capability names, lint globs (`+*`, empty capability list, overly-broad `*`), and check TTL formats. It also renders a *preview* allow/deny per test case for responsiveness. This preview is explicitly labelled as non-authoritative.
- **Backend dry-run** provides the authoritative verdict, shown on demand and before save. A new endpoint parses the draft HCL, constructs an in-memory `ACL`, and evaluates each `(path, capability)` case using the exact production matcher — so group/scope/templated rules resolve correctly and the client simulator can never silently drift from server behaviour.

### New backend surface

```
POST /v1/sys/policies/acl/test
  body: { "policy": "<draft HCL>", "cases": [ { "path": "...", "capability": "read" }, ... ] }
  resp: {
    "parse_ok": true,
    "errors": [],                              # parse/lint errors with message (+ line/col when available)
    "results": [
      { "path": "...", "capability": "read",
        "allowed": true,
        "matched_path": "secret/data/team/+/*", # the rule that decided it
        "match_kind": "segment_wildcard",        # exact | prefix | segment_wildcard | none
        "denied_by_deny": false }
    ]
  }
```

- The endpoint is **stateless** — it never writes the policy. It requires the same capability as `write_policy` on `sys/policies/acl/*` so it is not an information-disclosure primitive beyond what the caller could already author.
- Reuses the existing parser (`PolicyConfig::parse`) and the `ACL` builder + matcher; no new evaluation logic.

A companion Tauri command `policy_test(policy: String, cases: Vec<PolicyTestCase>)` wraps it in [`gui/src-tauri/src/commands/policies.rs`](../gui/src-tauri/src/commands/policies.rs), with a TS wrapper in [`gui/src/lib/api.ts`](../gui/src/lib/api.ts).

### Test-case persistence

Saved test cases live alongside the policy, not inside its HCL:

- Stored under a sibling key `policy-tests/<name>` (JSON: an array of `{ path, capability, expect: "allow" | "deny", note? }`).
- New commands: `read_policy_tests(name)` / `write_policy_tests(name, cases)` (HTTP `GET/PUT /v1/sys/policies/acl/<name>/tests`).
- On save, the GUI runs all saved cases through the dry-run endpoint against the *draft* text; a failing case blocks save with an explicit override ("save anyway"). The pass/fail summary ("3 / 3 cases pass") is shown next to the Save button.

### GUI structure

The Policies page detail panel gains a third tab; the existing two are unchanged:

- **Visual builder** — `PolicyBlockEditor` component. Each path rule is a `Card` with: a path `Input` + live glob lint badge, capability toggle chips, and an "add" affordance that reveals collapsible sub-editors for required/allowed/denied parameters, `min/max_wrapping_ttl`, and `groups` / `scopes`. Drag-reorder via the existing patterns. A live HCL preview pane shows the serialized output. If HCL from the source tab fails to parse into blocks, the builder shows the parse error and keeps the operator on the source tab rather than silently dropping content.
- **HCL source** — the existing `<textarea>` editor (kept verbatim; the builder is additive).
- **Validate & test** — `PolicyValidatorPanel`. Top section: lint/parse results list (errors + warnings). Bottom section: editable test-case rows, each showing the authoritative allow/deny verdict and matched rule after a "Run" click, plus the saved-case regression summary.

Round-trip rule: **HCL is the source of truth.** The builder serializes *to* HCL on every change and re-parses *from* HCL when the source tab is edited, so the two views never diverge.

### Components reused

`Card`, `Button`, `Badge`, `Input`, `Select`, `Tabs`, `Modal`, `ConfirmModal`, `useToast`, and `PolicyHistoryPanel`. [`RustionPolicyTierEditor`](../gui/src/components/RustionPolicyTierEditor.tsx) is the precedent for a multi-field policy form. No new component library; no Monaco/CodeMirror dependency is required (the source tab stays a `<textarea>`; syntax highlighting is an optional later enhancement).

## Phases

See the [roadmap](../roadmaps/policy-builder-validator.md) for full phase notes and acceptance criteria. In brief:

1. **Backend dry-run** — `POST /v1/sys/policies/acl/test` + `policy_test` Tauri command + TS wrapper. Authoritative, stateless.
2. **Client lint + simulator** — TS HCL→blocks parser, capability/glob/TTL lint, non-authoritative preview verdict.
3. **Visual builder tab** — `PolicyBlockEditor`, block cards, capability toggles, dynamic blocks, drag-reorder, HCL ⇄ blocks round-trip.
4. **Validate & test tab** — `PolicyValidatorPanel`, savable test cases (`policy-tests/<name>`), save-time regression gate with override.
5. **Polish & docs** — history integration, `vitest` coverage for the TS parser/simulator, Rust tests for the dry-run endpoint, operator docs.

## Testing

- **Rust** — unit tests for `POST .../test`: parse-error reporting, each `match_kind` (exact / prefix / segment_wildcard / none), `deny` precedence, group/scope-gated cases, and the `+*` rejection. Assert the endpoint never persists.
- **TS (`vitest`)** — round-trip property test (HCL → blocks → HCL is stable for a corpus of real policies including `administrator`, `default`, `totp-admin`), lint detection cases, and parity spot-checks where the client preview must agree with the backend verdict.
- **e2e** — author a policy in the builder, save, confirm the stored HCL parses server-side and that saved test cases gate a regressive edit.

## Out of scope (deferred follow-ups)

- Monaco/CodeMirror syntax highlighting for the source tab.
- Templated-path (`{{identity.entity.id}}`) live preview with a sample identity — the dry-run reports templated rules but does not render them against a hypothetical entity in v1.
- Policy diff/compare across two named policies.
- Sentinel / RGP (role-governing policy) authoring.
