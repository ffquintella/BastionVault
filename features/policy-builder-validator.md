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

- **Complete (all 5 phases).** Implemented end-to-end with automated coverage. Two deliberate deviations from this spec's original draft, both noted inline below:
  1. **`v2/` not `v1/`.** Per `agent.md` (which `CLAUDE.md` says overrides everything), all new HTTP routes are introduced under `v2/`. The dry-run is `POST /v2/sys/policies/acl/test`; `v1` remains frozen for Vault compatibility.
  2. **Test-case persistence path.** Saved cases live at `GET`/`POST /v2/sys/policy-tests/{name}` (a sibling top-level route, like `capabilities-self`) rather than `/v1/sys/policies/acl/<name>/tests`. This avoids the `policies/acl/{name}` catch-all route shadowing the sub-resource and works in both embedded and remote GUI modes through a dedicated HTTP shim. `test` is consequently a reserved policy name (the dry-run owns `policies/acl/test`).
- Backend: `ACL::explain_capability` ([`acl.rs`](../crates/bv-kernel/src/modules/policy/acl.rs)) reuses the production matcher for the verdict; `PolicyModule::handle_policy_test` / `handle_policy_tests_*` ([`mod.rs`](../crates/bv-kernel/src/modules/policy/mod.rs)); `PolicyStore::{get,set}_policy_tests_ns` ([`policy_store.rs`](../crates/bv-kernel/src/modules/policy/policy_store.rs)). Rust tests: `test_explain_capability_*`, `test_policy_acl_dry_run_endpoint`, `test_policy_acl_dry_run_multi_policy`, `test_policy_tests_persistence_endpoint`.
- **Multi-policy effectivity is implemented** (see the section below): a case is evaluated against the draft plus the policies a token carries alongside it, defaulting to `default`, and the response names the policy that contributed the winning rule.
- Client: [`gui/src/lib/policyHcl.ts`](../gui/src/lib/policyHcl.ts) (parser/serializer/lint/multi-policy preview, 31 `vitest` cases in [`policyHcl.test.ts`](../gui/src/test/policyHcl.test.ts)); [`PolicyBlockEditor.tsx`](../gui/src/components/PolicyBlockEditor.tsx) and [`PolicyValidatorPanel.tsx`](../gui/src/components/PolicyValidatorPanel.tsx); Tauri commands `policy_test` / `read_policy_tests` / `write_policy_tests`.
- The Policies page now has four tabs: **Visual builder**, **HCL source**, **Validate & test**, **History**. Interactive (live-app) verification requires `make run-dev-gui` — the browser preview has no Tauri `invoke` bridge.

### Original draft note

- The companion [roadmap](../roadmaps/policy-builder-validator.md) was drafted alongside this spec.
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
3. **Segment-wildcard** rules (`+` matches exactly one *non-empty* path segment). The non-empty part matters: a LIST is issued against a collection path with a trailing slash (`rustion/targets/`), which splits to a trailing empty segment, so `path "x/+"` governs the *children* of `x` and never the collection itself. Grant a collection explicitly (`path "x"` or `path "x/*"`). Before this was enforced, `+` swallowed the empty segment and a read-only child rule became the most specific match for the collection — and since precedence picks one winner rather than unioning across policies, `default`'s `rustion/targets/+` silently downgraded every non-root token holding `path "*"`.
4. **Group-gated** (`groups = [...]`) and **scope-filtered** (`scopes = [...]`) rules are evaluated as additional gates at authorize time, not merged into the base trie.
5. `deny` on any matching rule overrides all granted capabilities.

The illegal `+*` combination (a segment wildcard immediately followed by a prefix wildcard) is rejected by the parser and must be caught by the client lint before save.

### One winner, not a union: how multiple policies combine

This is the single most misread part of the model, so the simulator states it explicitly and the lint warns on it.

Capabilities are unioned **only between rules whose path string is identical**. That merge happens once, when the ACL is built (`ACL::new` → `ACL::get_permissions` → `Permissions::merge`). Across *different* path strings there is no union at all: the precedence list above selects exactly one winning rule (`ACL::allow_operation` consults `exact_rules` first; `ACL::get_none_exact_paths_permissions` sorts the remaining candidates and takes the last one), and that rule's capabilities are the answer.

The consequence operators trip over: **a narrow rule in one policy replaces a broad rule in another.** A token carrying both

```hcl
# policy "administrator"
path "*"                { capabilities = ["create", "read", "update", "delete", "list", "sudo"] }

# policy "default"
path "sys/capabilities-self" { capabilities = ["update"] }
```

holds `["update"]` on `sys/capabilities-self` — not the union. `sys/capabilities-self` reports this faithfully, and so does the dry-run once the case names the attached policy (see [Multi-policy effectivity](#multi-policy-effectivity)); either is a fast way to diagnose it.

This is HashiCorp Vault's behaviour and BastionVault matches it deliberately. It is not a bug to be smoothed over: operators rely on a narrow rule out-specifying a broad one in order to *restrict*, so making the matcher union across policies would silently widen, on upgrade, every deployment built on that. The three remedies, in order of preference:

1. **Restate the path in the broad policy.** Identical path strings merge, so `path "sys/capabilities-self" { capabilities = [...all...] }` in the admin policy restores the full set. This is what `ADMINISTRATOR_POLICY` does for all 33 restatable `default` rules; `mod default_policy_does_not_narrow_admins_tests` in `policy_store.rs` sweeps `default` and fails if one is missing, so a rule added to `default` cannot silently re-narrow every administrator.
2. **Drop `default` from the token** — `token_no_default_policy` on the auth mount / role (`bv-utils` `token_util.rs`).
3. **Widen the rule in `default`** — almost always wrong, because `default` is attached to every token, so widening it widens every tenant.

Two rule kinds are exempt from single-winner selection by construction, and need no restatement: **group-gated** (`groups = [...]`) and **scope-filtered** (`scopes = [...]`) rules are stored unmerged and layered *additively* onto the base verdict at authorize time, because each carries a per-request gate that merging would destroy. This is why `default`'s `resources/*`, `secret/*` and `resource-group/groups/+` rules do not narrow an administrator while its ungated rules do. **Templated** paths (`{{identity.entity.id}}`) are also unrestatable — a non-templated policy cannot name a per-caller path.

Narrowing is only *observable* where the withheld capability has a handler behind it. `default` granting `update` on a Write-only route, or `list` on a List-only collection, costs an administrator nothing even though `sys/capabilities-self` shows the short list (`Operation::Write` maps to `Capability::Update`; see `Permissions::check`). The one case where it cost real function was `rustion/targets/+`: `read` alone, against a route serving Read, Write and Delete.


### Hybrid evaluation engine

The effectivity verdict uses a **hybrid** approach (decided during design review):

- **Client-side TypeScript** provides instant feedback while typing — tokenize HCL into the block model, validate capability names, lint globs (`+*`, empty capability list, overly-broad `*`), and check TTL formats. It also renders a *preview* allow/deny per test case for responsiveness. This preview is explicitly labelled as non-authoritative.
- **Backend dry-run** provides the authoritative verdict, shown on demand and before save. A new endpoint parses the draft HCL, constructs an in-memory `ACL`, and evaluates each `(path, capability)` case using the exact production matcher — so group/scope/templated rules resolve correctly and the client simulator can never silently drift from server behaviour.

### New backend surface

Shipped shape (the route is `v2/`, not the `v1/` this draft first named —
see Current State):

```
POST /v2/sys/policies/acl/test
  body: {
    "policy": "<draft HCL>",
    "name":   "team-reader",                   # name the draft would be saved under
    "cases":  [ { "path": "...", "capability": "read",
                  "env": "staging",            # optional; exercises param constraints
                  "policies": ["default"] },   # optional; absent = ["default"], [] = draft alone
                ... ]
  }
  resp: {
    "parse_ok": true,
    "errors": [],                              # parse/lint errors with message (+ line/col when available)
    "results": [
      { "path": "...", "capability": "read",
        "allowed": true,
        "matched_path": "secret/data/team/+/*", # the rule that decided it
        "match_kind": "segment_wildcard",       # exact | prefix | segment_wildcard | none
        "denied_by_deny": false,
        "granting_policies": ["default"],       # who wrote the winning rule
        "evaluated_policies": ["team-reader", "default"],
        "missing_policies": [],                 # named but nonexistent
        "draft_only_allowed": true }            # verdict of the draft alone
    ]
  }
```

- The endpoint is **stateless** — it never writes the policy. It requires the same capability as `write_policy` on `sys/policies/acl/*` so it is not an information-disclosure primitive beyond what the caller could already author. Attached policies are read through the same store the caller could already read them from.
- Reuses the existing parser (`PolicyConfig::parse`) and the `ACL` builder + matcher; no new evaluation logic. One `ACL` is built per distinct attached-policy set and memoized across the cases that share it.
- See [Multi-policy effectivity](#multi-policy-effectivity) for what `policies` / `granting_policies` / `draft_only_allowed` are for.

A companion Tauri command `policy_test(policy, cases, name)` wraps it in [`gui/src-tauri/src/commands/policies.rs`](../gui/src-tauri/src/commands/policies.rs), with a TS wrapper in [`gui/src/lib/api.ts`](../gui/src/lib/api.ts).

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

## Effectivity test cases: environment + value assertions

Beyond the base `(path, capability, expect)` assertion, a case carries three
optional fields (persisted on `PolicyTestCase`, omitted when empty):

- **`env`** — fed to the dry-run matcher as the `env` request parameter. This
  is the one place the dry-run leaves its bitmap-only mode: when `env` is set,
  `handle_policy_test` routes the case through
  `ACL::explain_capability_with_params`, which maps the capability to a real
  `Operation` and runs the production matcher with `check_only = false` — the
  only path that evaluates the governing rule's `required_parameters` /
  `allowed_parameters` / `denied_parameters` (i.e. the visual builder's
  "Restrict to environments"). An empty/absent `env` is byte-for-byte the old
  bitmap-only dry-run, so env-less cases and the **regression gate keep their
  existing behavior**; the gate feeds each saved case's `env` when present so
  gating stays consistent with what an operator tested.
- **`expect_key` / `expect_value`** — a value assertion. At **Run** time the
  GUI reads the live secret at the case's `<mount>/data/<path>` in the chosen
  `env` and the case passes only if the allow verdict holds **and** the live
  value equals `expect_value`. This is a Run-time convenience check that reads
  live state; it is deliberately **not** enforced by the save-time regression
  gate (which must not couple a policy save to mutable secret contents). Value
  assertions only apply to `read` on a KV v2 data path; other paths report
  "not a kv-v2 data path".

## Multi-policy effectivity

A test case is evaluated against the draft **plus the policies a real token
carries alongside it**, built into one `ACL` and run through the production
matcher. Without this the validator could not see the defect class described
under "One winner, not a union": an operator validating an admin draft saw
the full capability set and never learned that `default` — attached to every
token — out-specifies it on the 35 paths it names. That is exactly the
`rustion/targets/+` narrowing fixed in `policy_store.rs`, and diagnosing it
used to mean minting a token and calling `sys/capabilities-self`.

Each case carries an optional `policies` array, and it is **tri-state**
because the three states mean different things:

| `policies` | meaning |
|---|---|
| absent / `null` | `["default"]` — what a normal token carries, so an unqualified case reports production reality |
| `[]` | the draft alone — the original single-policy dry-run, kept as an explicit opt-out |
| `["a", "b"]` | the draft plus exactly those |

Absent defaults to `default` rather than to the draft alone on purpose: the
draft-alone verdict is the one that misled operators. Nothing is lost by it,
because every row also reports `draft_only_allowed` — the verdict the draft
would give on its own. When that disagrees with `allowed`, the difference
*is* the cross-policy narrowing, and `granting_policies` names the policy
whose rule won. The GUI tags such a row **narrowed** and points at the
remedy (restate that exact path, since identical path strings do merge).

Details that matter:

- **`name`.** The request carries the name the draft would be saved under
  (a policy's name comes from the URL, not the HCL). It attributes the
  draft's own rules in `granting_policies`, and it is how an attached policy
  that *is* the draft is recognized and skipped — an operator editing
  `default` must not have the stored `default` merged back in underneath.
  `evaluated_policies` then reports the single entry, so the substitution is
  visible rather than implied.
- **`root` is refused, not filtered.** An ACL containing `root` allows every
  path and `ACL::new` rejects it alongside any sibling, so naming it returns
  `400` instead of quietly evaluating a different set.
- **The caller must be able to read what it attaches.** Attaching a policy
  reads it, so the handler checks the caller's own `read` on
  `sys/policies/acl/<name>` (against an ACL built from the token's own
  policies, exactly as the request pipeline does) and returns `403`
  otherwise. Without it the dry-run would be a read oracle for a caller
  holding `update` on `sys/policies/acl/test` but not `read` on the policy it
  names: attach it to an empty draft and the per-case `matched_path` /
  `allowed` pairs recover its rules. That ACL shape is unusual — a caller who
  can write any policy can rewrite `default` and escalate anyway — but the
  endpoint's contract is that it discloses nothing the caller could not
  already reach. It fails closed rather than evaluating the readable subset:
  an optimistically-wide verdict is the exact failure this feature exists to
  prevent, which is also why a *missing* policy is only reported (it is in no
  token's ACL either) while an unreadable one is refused.
- **A missing attached policy is reported** in `missing_policies`. Dropping
  it silently would leave the ACL narrower than the token it models.
- **Gated rules still do not narrow.** `groups`/`scopes`-filtered rules are
  stored unmerged and layered additively at authorize time, so they never
  out-specify an ungated rule. Both the backend (by construction) and the
  client preview (`flattenRules` excludes them) preserve this — which is why
  `default`'s scope-gated `secret/*` does not appear to narrow an admin.
- **`granting_policies` unions across every capability bit**, not just the
  one under test. The case that needs explaining is the one where the
  capability was *withheld*, and there the tested bit has no entry at all.
- **The save-time regression gate replays each saved case's `policies`**, so
  gating stays consistent with what the operator tested. A case saved before
  this existed has no `policies` field and therefore starts reporting the
  cross-policy verdict — deliberately, since that is the verdict its token
  gets.

Backend: `ACL::locate_match` resolves the winning rule's `Permissions` and
`granting_policy_names` reads its `granting_policies_map`, surfaced as
`CapabilityExplain::granting_policies`; `PolicyModule::handle_policy_test`
memoizes one `ACL` per distinct attached-policy set. Client:
`previewCapability(model, path, cap, attached)` mirrors the merge offline;
`PolicyValidatorPanel` exposes a per-row **With policies** field
(blank = `default`; the panel deliberately offers no draft-alone control,
because `draft_only_allowed` already reports that verdict on every row).
Tests:
`test_explain_capability_names_granting_policies`,
`test_policy_acl_dry_run_multi_policy`, the tri-state round trip in
`test_policy_tests_persistence_endpoint`, and
`describe("policyHcl — multi-policy preview")`.

## Out of scope (deferred follow-ups)

- Monaco/CodeMirror syntax highlighting for the source tab.
- Templated-path (`{{identity.entity.id}}`) live preview with a sample identity — the dry-run reports templated rules but does not render them against a hypothetical entity in v1.
- Policy diff/compare across two named policies.
- Sentinel / RGP (role-governing policy) authoring.
