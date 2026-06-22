# Graphical Policy Builder & Validator

The Policies page in the desktop GUI provides a visual, block-based editor
and an effectivity validator **beside** the textual HCL editor. HCL remains
the source of truth — the builder serializes to and parses from it, so you
can move between views freely. Nothing here replaces the HCL editor.

## Why

ACL policies are the highest-blast-radius object in the vault: a stray `*`
or a forgotten `deny` silently over- or under-grants every token mapped to
the policy. The builder reduces the chance of writing a bad policy; the
validator proves what a policy actually grants **before** it is applied to
live tokens.

## The four tabs

When you select a policy you get four tabs:

- **Visual builder** — each `path "..." { ... }` rule is a card with a path
  field, a live glob lint badge (`exact` / `prefix` / `segment +` /
  `matches everything` / `invalid +*`), capability toggle chips, reorder
  controls, and a collapsible **Advanced** section for TTL bounds, required
  parameters, asset-group (`groups`) and ownership-scope (`scopes`) filters.
  A collapsible **HCL preview** shows the serialized output.
  - `deny` is mutually exclusive: turning it on greys the rest (it always
    wins on merge).
  - `sudo` is flagged as root-equivalent on the matched path.
  - `connect` grants brokered session access without exposing the stored
    credential.
  - `root` is shown disabled — it is a policy-level concept, not a per-path
    grant.
  - If the HCL fails to parse, the builder shows the error and asks you to
    fix it on the **HCL source** tab; your content is never dropped.
- **HCL source** — the plain text editor, unchanged.
- **Validate & test** — see below.
- **History** — before/after diffs and restore (unchanged).

## Validate & test

The top section lists client-side lint and parse findings over the current
draft (unknown capabilities, empty capability lists, the forbidden `+*`
combination, overly-broad `*`, invalid TTL formats). These are instant but
**non-authoritative**.

The bottom section holds editable **test cases** — `(path, capability,
expect)` rows. Click **Run** to evaluate them against the **authoritative**
backend matcher: the server parses your draft, builds an in-memory ACL, and
reports each verdict (allow/deny), the rule that decided it (`matched_path`
+ `match_kind`), and whether it passed your expectation. Click **Save
cases** to persist them with the policy.

### Saved cases gate the save

Saved test cases double as a regression gate. When you save a policy, the
GUI runs every saved case against the draft through the dry-run endpoint. If
any case fails, the save is blocked with an explicit **Save anyway**
override and a summary of how many cases failed. This catches a regressive
edit that quietly breaks an intent you previously documented.

Test cases are stored **alongside** the policy, not inside its HCL, so a
restore of a historical policy version never clobbers your present-day
cases. (If a restore makes a saved case fail, the gate surfaces it on the
next save.)

## Hybrid evaluation engine

Two layers cooperate:

- **Client-side preview** (TypeScript) — instant feedback while typing.
  Mirrors the backend's `exact > prefix > segment` precedence but is
  explicitly labelled non-authoritative and never gates a save on its own.
- **Backend dry-run** — the authoritative verdict. A stateless endpoint
  parses the draft and evaluates each case with the exact production
  matcher, so group/scope/templated rules resolve the same way they do at
  authorize time. The simulator can never silently drift from production.

## API

See the [API reference](api.md#policies):

- `POST /v2/sys/policies/acl/test` — stateless dry-run (never persists).
  Requires the same capability as a policy write (`sys/policies/acl/*`).
- `GET` / `POST /v2/sys/policy-tests/{name}` — read / write saved test
  cases.

> **Reserved name:** because the dry-run owns `policies/acl/test`, you
> cannot create a policy literally named `test`.

## Limitations (v1)

- Templated paths (`{{identity.entity.id}}`) are reported by the dry-run but
  not rendered against a hypothetical sample identity.
- Group- and scope-gated rules cannot fully resolve in a stateless dry-run
  (they need a caller identity and a concrete target), so they reflect only
  the ungated grant.
- Allowed/denied parameter **maps** are preserved on round-trip but are
  edited from the HCL source tab, not the visual builder.
- No syntax highlighting on the source tab (a deferred enhancement).
