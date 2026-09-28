# Project Tracking Format (PTF) — v1

A plain-Markdown convention for two files, `ROADMAP.md` and `CHANGELOG.md`, that
together let a human or a tool answer, for any project:

- What are we trying to reach (milestones) and how is each one broken down (tasks)?
- How are milestones grouped into larger phases (optional)?
- Which spec/design document describes each piece of work?
- What is done, in progress, blocked, postponed or abandoned — and why?
- In which release did each task ship?

This document is the normative specification. It is written for both people and
agents (LLMs, linters, the Project Tracker app). Words in CAPITALS (MUST, SHOULD,
MAY) follow RFC 2119.

PTF is built on existing conventions rather than inventing new ones:

| Concern | Base convention | What PTF adds |
|---|---|---|
| Changelog structure | [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/) | Two extra categories (`Postponed`, `Abandoned`), mandatory references |
| Entry references | [Common Changelog](https://common-changelog.org/) trailing `(refs)` group | Same syntax reused in the roadmap |
| Task states | Multi-state checkboxes (`[ ]`, `[/]`, `[x]`, `[>]`, `[-]`, `[!]`) as popularised by Obsidian themes | Fixed meaning per symbol, transition rules |
| Roadmap horizons | Now / Next / Later | Milestones = committed scope, `Backlog` = later |
| Grouping milestones | — | Optional `Phases` layer (`P<n>`), same reference-table pattern as `Specs` |
| Dates | ISO 8601 | — |

---

## 1. Files and identity

1. A project MUST have `ROADMAP.md` and `CHANGELOG.md` at the repository root.
2. Both files MUST start with a YAML front matter block declaring the format:

   ```markdown
   ---
   ptf: 1
   project: project-tracker
   ---
   ```

   `ptf` is the format version (integer). `project` is a short slug, identical in
   both files. Tools use the front matter to detect PTF files; files without it
   are treated as free-form Markdown.
3. Files MUST be UTF-8, use `-` as the list marker, and use ATX headings (`#`).

---

## 2. Identifiers

Every trackable thing has a short, stable, globally unique ID:

| Kind | Pattern | Example | Defined in |
|---|---|---|---|
| Phase | `P<n>` | `P1` | `ROADMAP.md`, `## Phases` table |
| Milestone | `M<n>` | `M3` | `ROADMAP.md`, one `##` heading each |
| Task | `T<n>` | `T12` | `ROADMAP.md`, one task-list line each |
| Spec | `S<n>` | `S2` | `ROADMAP.md`, `## Specs` table |

Rules:

- `<n>` is a positive integer with no padding (`T7`, not `T007`).
- IDs are assigned as `max(existing) + 1` for that kind and are **never reused**,
  even after a task is abandoned or deleted.
- An ID is *defined* exactly once (in its heading, task line or table row) and may
  be *referenced* any number of times in either file.
- IDs are case-sensitive and always uppercase.

### 2.1 Reference groups

A reference group is a parenthesised, comma-separated list of references placed
**at the end of a line**:

```
- Add repository registry screen (T3, S2, #14)
```

A reference is one of:

- a PTF ID: `P1`, `M3`, `T12`, `S2`
- an issue/PR number: `#14`
- an inline Markdown link: `[design](docs/design/registry.md)`

Only the **last** parenthesised group on the line is parsed as references, and
only if every item matches one of the forms above. Any other parentheses are
plain text.

---

## 3. `ROADMAP.md`

### 3.1 Layout

```markdown
---
ptf: 1
project: <slug>
---

# Roadmap

<free-form intro: mission, one or two paragraphs>

## [M1] <Milestone title>
> outcome: <one sentence — what is true when this milestone is done>
> target: <YYYY-MM | YYYY-MM-DD>            (optional)
> version: <semver the milestone maps to>  (optional)
> phase: <P<n> this milestone belongs to>  (optional, see 3.9)
> status: <postponed | abandoned>           (only when overriding, see 3.3)

- [x] T1 <Task title> (S1)
- [/] T2 <Task title> (S1, #12)
- [ ] T3 <Task title>
  - blocked-by: T2

## [M2] <Milestone title>
> outcome: ...

- [ ] T4 ...

## Backlog
- [ ] T9 <Idea not yet scheduled>
- [>] T7 <Task postponed out of a milestone> (S3)
  - from: M2

## Specs
| ID | Title | Path |
|----|-------|------|
| S1 | Application architecture | docs/specs/architecture.md |
| S2 | Repository registry      | docs/specs/registry.md |

## Phases
| ID | Title | Outcome | Target |
|----|-------|---------|--------|
| P1 | MVP   | A single user can track one repository end to end. | 2026-12 |
```

### 3.2 Milestones

- A milestone is a `##` heading of the form `## [M<n>] Title`.
- Milestones MAY instead be `###` headings (`### [M<n>] Title`) nested under a
  free-form `##` heading that groups them (e.g. `## Track 1 — Core`). The
  grouping heading's text becomes the milestone's `group` (6.1); it carries no
  ID, status or metadata of its own. Use `## Phases` when the grouping needs
  those.
- Milestones are listed in **intended delivery order**, top to bottom. IDs need
  not be sequential in that order (a later-created milestone may be inserted
  earlier).
- Immediately after the heading, a **blockquote metadata block** MAY appear. Each
  line is `> key: value`. Recognised keys:

  | key | required | meaning |
  |---|---|---|
  | `outcome` | SHOULD | one sentence, the "done when" statement |
  | `target` | MAY | planned date, `YYYY-MM` or `YYYY-MM-DD` |
  | `version` | MAY | the release version this milestone is expected to ship in |
  | `phase` | MAY | the `P<n>` this milestone belongs to (see 3.9); must have a row in `## Phases` |
  | `status` | MAY | explicit override, only `postponed` or `abandoned` (see 3.3) |
  | `spec` | MAY | comma-separated spec IDs governing the whole milestone |

  Unknown keys are preserved by tools but ignored. A long value MAY wrap onto
  following `> ` lines that don't start with `key:`; they continue the previous
  key's value, joined with a space.
- After the metadata block, a single task list contains the milestone's tasks.
  Free-form paragraphs between the metadata and the list are allowed.

### 3.3 Milestone status

Milestone status is **derived** from its tasks unless overridden:

| Derived status | Rule |
|---|---|
| `done` | every task is `[x]` or `[-]`, and at least one is `[x]` |
| `active` | at least one task is `[/]` or `[!]`, or at least one `[x]` while others remain open |
| `planned` | otherwise (all tasks `[ ]`/`[>]`, or no tasks yet) |

Explicit override via `> status:` is allowed **only** for:

- `postponed` — the milestone as a whole is pushed out. Its open tasks stay under
  it. A `Postponed` changelog entry referencing the milestone MUST exist.
- `abandoned` — the milestone will not happen. Its open tasks MUST each be marked
  `[-]` (or moved elsewhere). An `Abandoned` changelog entry MUST exist.

### 3.4 Tasks

A task is one task-list line:

```
- [<state>] T<n> <Title> (<refs>)
  - <key>: <value>
```

- `<state>` is exactly one character from the table below.
- `T<n>` immediately follows the checkbox and is the task's definition.
- `<Title>` is a short imperative phrase ("Add repository registry", not "Registry").
- `(<refs>)` is an optional reference group (see 2.1) — typically the spec IDs the
  task implements and any issue numbers.
- Nested bullets, if present, are `key: value` metadata for that task. Tasks MUST
  NOT have nested sub-tasks; split into more tasks instead.

Recognised task metadata keys:

| key | when | meaning |
|---|---|---|
| `from` | required when state is `[>]` | the milestone the task was postponed out of |
| `blocked-by` | required when state is `[!]` | comma-separated IDs or free text |
| `why` | SHOULD for `[>]` and `[-]` | short reason (the full reason lives in the changelog entry) |
| `due` | MAY | `YYYY-MM-DD` |
| `owner` | MAY | handle or name |
| `note` | MAY | anything else |

### 3.5 Task states

| Checkbox | State | Meaning |
|---|---|---|
| `[ ]` | **planned** | not started |
| `[/]` | **in progress** | someone is actively working on it |
| `[!]` | **blocked** | cannot progress; `blocked-by` says why |
| `[x]` | **done** | finished and recorded in the changelog |
| `[>]` | **postponed** | deliberately pushed to a later milestone or to `Backlog` |
| `[-]` | **abandoned** | will not be done; kept for history |

`[X]` (uppercase) is accepted on read and normalised to `[x]` on write.

### 3.6 State transitions and their side effects

The file only records *state*; the *event* (with date and reason) is recorded in
`CHANGELOG.md`. The two MUST be kept consistent:

| Transition | Roadmap change | Changelog change (under `## [Unreleased]`) |
|---|---|---|
| create task | add `- [ ] T<n> …` under a milestone or `Backlog` | none |
| start | `[ ]`/`[>]`/`[!]` → `[/]` | none |
| block | any open state → `[!]`, add `blocked-by` | none |
| finish | → `[x]` | MUST add an entry in `Added`/`Changed`/`Fixed`/… referencing `T<n>` |
| postpone | → `[>]`; **move the line** to the target milestone or `Backlog`; add `from: M<old>` | MUST add an entry under `### Postponed` referencing `T<n>` with the reason |
| abandon | → `[-]`; line stays where it is | MUST add an entry under `### Abandoned` referencing `T<n>` with the reason |
| reschedule a postponed task | move the `[>]` line to its new milestone (keep `from`) | none (already logged) |
| resume | `[>]`/`[-]` → `[ ]` or `[/]`; remove `from` | SHOULD add a `Changed` entry ("Resume …") referencing `T<n>` |

A task MUST appear exactly once in the file. Postponing **moves** the line; it
never copies it.

### 3.7 `## Backlog`

An optional section for tasks not committed to any milestone (the "Later"
horizon). It contains a single task list. Tasks here are `[ ]` (new ideas) or
`[>]` (postponed with nowhere to land yet). Tasks in `Backlog` MUST NOT be `[/]`
or `[x]` — move them into a milestone first.

### 3.8 `## Specs`

An optional section holding a table of specification/design documents:

```markdown
| ID | Title | Path |
|----|-------|------|
| S1 | Application architecture | docs/specs/architecture.md |
```

- `ID` is `S<n>`, defined here and only here.
- `Path` is a repository-relative path or an absolute URL.
- Every `S<n>` referenced anywhere in either file MUST have a row here.
- A row MAY have a fourth column `Status` (`draft`, `approved`, `superseded`).

### 3.9 `## Phases`

An optional section for grouping milestones into a larger horizon (an epic, a
release train, a quarter). Phases are a pure grouping layer: they do not carry
their own tasks and are not referenced from `CHANGELOG.md`.

```markdown
## Phases
| ID | Title | Outcome | Target |
|----|-------|---------|--------|
| P1 | MVP   | A single user can track one repository end to end. | 2026-12 |
| P2 | Multi-repo & reports | Several repositories are indexed and exportable. |  |
```

- `ID` is `P<n>`, defined here and only here.
- `Title` is required. `Outcome` and `Target` (`YYYY-MM` or `YYYY-MM-DD`) are MAY
  columns and may be left empty.
- A milestone joins a phase by setting `phase: P<n>` in its metadata block
  (3.2). A milestone MAY have no `phase`; not every project needs phases.
- Every `phase` value referenced by a milestone MUST have a row here.
- Phase order (table row order) is the intended delivery order for phases.
  Milestones belonging to the same phase SHOULD be contiguous in `ROADMAP.md`,
  but this is not enforced.
- Phase status is **derived** from its milestones' statuses (3.3), the same way
  milestone status is derived from tasks:

  | Derived status | Rule |
  |---|---|
  | `done` | every milestone in the phase is `done` or `abandoned`, and at least one is `done` |
  | `active` | at least one milestone in the phase is `active` |
  | `planned` | otherwise |

  Phases have no explicit status override and no changelog entries of their
  own — they are a read-only view computed from the milestones that reference
  them.

---

## 4. `CHANGELOG.md`

### 4.1 Layout

```markdown
---
ptf: 1
project: <slug>
---

# Changelog

<one paragraph: what this file is, link to Keep a Changelog and SemVer>

## [Unreleased]

### Added
- <Imperative description> (T12, S2)

### Postponed
- <Task title> to M4: <reason> (T7)

## [0.2.0] - 2026-10-15

### Added
- ...

### Fixed
- ...

## [0.1.0] - 2026-09-28

### Added
- Scaffold the desktop app with Tauri and TypeScript (T1, M1)

[Unreleased]: https://…/compare/v0.2.0...HEAD
[0.2.0]: https://…/compare/v0.1.0...v0.2.0
[0.1.0]: https://…/releases/tag/v0.1.0
```

### 4.2 Releases

- Follows Keep a Changelog 1.1.0: `## [Unreleased]` MUST exist and be first;
  releases follow, newest first, as `## [<semver>] - <YYYY-MM-DD>`; a withdrawn
  release is suffixed `[YANKED]`.
- Bottom-of-file link references (`[1.0.0]: url`) SHOULD be present when the
  project is hosted somewhere linkable.

### 4.3 Categories

Within a release, changes are grouped under `###` headings, in this fixed order,
omitting empty ones:

| Category | Source | Use for |
|---|---|---|
| `Added` | KaC | new capability |
| `Changed` | KaC | behaviour change of existing capability |
| `Deprecated` | KaC | still works, will be removed |
| `Removed` | KaC | capability removed |
| `Fixed` | KaC | bug fixes |
| `Security` | KaC | vulnerability fixes |
| `Postponed` | **PTF** | tasks/milestones pushed to a later milestone or to backlog |
| `Abandoned` | **PTF** | tasks/milestones that will not be done |

`Postponed` and `Abandoned` record *planning decisions*, so that a reader of the
changelog alone can see what fell out of a release and why.

### 4.4 Entries

```
- <Description> (<refs>)
```

- `<Description>` is a single sentence in imperative mood ("Add…", "Fix…",
  "Postpone… to M4: <reason>"), self-contained, written for humans.
- `(<refs>)` is a reference group (2.1). Every entry SHOULD reference at least
  one `T<n>` or `M<n>`; entries without any PTF reference are legal but tools
  report them as *untracked*.
- `Postponed`/`Abandoned` entries MUST reference the task or milestone and MUST
  state the reason in the description.
- One task MAY be referenced by several entries (e.g. an `Added` and a `Fixed`),
  and one entry MAY reference several tasks.

---

## 5. Cross-file invariants

A PTF-compliant pair of files satisfies all of the following. Tools SHOULD report
each violation with its code.

| Code | Invariant |
|---|---|
| PTF001 | Both files carry `ptf: 1` front matter with the same `project`. |
| PTF002 | Every ID is defined exactly once, in the correct file and place. |
| PTF003 | Every ID referenced anywhere is defined. |
| PTF004 | Every `[x]` task is referenced by at least one changelog entry in a non-`Postponed`/`Abandoned` category. |
| PTF005 | Every `[>]` task is referenced by at least one `Postponed` entry and has `from`. |
| PTF006 | Every `[-]` task is referenced by at least one `Abandoned` entry. |
| PTF007 | Every milestone with `status: postponed`/`abandoned` has a matching changelog entry. |
| PTF008 | Tasks in `Backlog` are only `[ ]` or `[>]`. |
| PTF009 | `[!]` tasks have `blocked-by`. |
| PTF010 | Changelog categories appear in the canonical order; `[Unreleased]` is first; dates are ISO 8601. |
| PTF011 | Every `S<n>` referenced has a row in `## Specs`. |
| PTF012 | No task line has nested task-list items (sub-tasks). |
| PTF013 | Every `phase` referenced by a milestone has a row in `## Phases`. |

---

## 6. Derived views (what a tool can compute)

Given only the two files, a tool can compute, without any other input:

- **Task → version**: the release section containing the first entry that
  references the task (or `Unreleased`).
- **Milestone status** (3.3) and **milestone progress**: `done / (total − abandoned)`.
- **Phase status** (3.9) and **phase progress**: same formula, one level up, over
  the milestones that reference the phase.
- **Timeline of decisions**: every `Postponed`/`Abandoned` entry, dated by its release.
- **Current focus**: all `[/]` and `[!]` tasks across milestones.
- **Spec coverage**: for each `S<n>`, the tasks and milestones that reference it.
- **Untracked work**: changelog entries with no PTF reference.

### 6.1 Canonical JSON shape

Tools exchanging parsed PTF data SHOULD use this shape:

```json
{
  "ptf": 1,
  "project": "project-tracker",
  "phases": [
    {
      "id": "P1", "title": "MVP", "order": 0,
      "outcome": "…", "target": "2026-12",
      "status": "active", "statusSource": "derived",
      "milestones": ["M1", "M2"]
    }
  ],
  "milestones": [
    {
      "id": "M1", "title": "App skeleton", "order": 0,
      "outcome": "…", "target": "2026-10", "version": "0.1.0",
      "status": "done", "statusSource": "derived",
      "phase": "P1",
      "group": "Track 1 — Core",
      "refs": ["S1"],
      "tasks": ["T1", "T2"]
    }
  ],
  "tasks": [
    {
      "id": "T1", "title": "Scaffold Tauri app", "state": "done",
      "milestone": "M1", "refs": ["S1"], "meta": {},
      "changelog": [{"version": "0.1.0", "date": "2026-09-28", "category": "Added"}]
    }
  ],
  "specs": [{"id": "S1", "title": "…", "path": "docs/specs/architecture.md"}],
  "releases": [
    {
      "version": "0.1.0", "date": "2026-09-28", "yanked": false,
      "entries": [{"category": "Added", "text": "…", "refs": ["T1", "M1"], "issues": ["#3"]}]
    }
  ],
  "diagnostics": [{"code": "PTF004", "message": "…", "file": "ROADMAP.md", "line": 42}]
}
```

`state` values: `planned | in-progress | blocked | done | postponed | abandoned`.
`status` values for milestones: `planned | active | done | postponed | abandoned`.
`status` values for phases: `planned | active | done` (no override, see 3.9).

---

## 7. Grammar (informative)

Line-oriented regular expressions a parser MAY use. `ID = (M|T|S|P)[1-9][0-9]*`.

```
front-matter     ^---$ … ^ptf: 1$ … ^project: [a-z0-9-]+$ … ^---$
milestone        ^(##|###) \[(M[1-9][0-9]*)\] (.+)$
milestone-meta   ^> ([a-z-]+): (.+)$
backlog          ^## Backlog$
specs            ^## Specs$
spec-row         ^\| (S[1-9][0-9]*) \| ([^|]+) \| ([^|]+) \|(?: ([^|]+) \|)?$
phases           ^## Phases$
phase-row        ^\| (P[1-9][0-9]*) \| ([^|]+) \|(?: ([^|]+) \|)?(?: ([^|]+) \|)?$
task             ^- \[([ /!xX>-])\] (T[1-9][0-9]*) (.+?)(?: \(([^()]+)\))?$
task-meta        ^  - ([a-z-]+): (.+)$
release          ^## \[(Unreleased|\d+\.\d+\.\d+[^\]]*)\](?: - (\d{4}-\d{2}-\d{2}))?( \[YANKED\])?$
category         ^### (Added|Changed|Deprecated|Removed|Fixed|Security|Postponed|Abandoned)$
entry            ^- (.+?)(?: \(([^()]+)\))?$
ref-group        split on `,\s*`; each item must match  ^(ID|#\d+|\[[^\]]+\]\([^)]+\))$
```

A line that looks like a task but has an invalid state character is a hard
error (PTF002), not a plain bullet.

---

## 8. Minimal complete example

`ROADMAP.md`

```markdown
---
ptf: 1
project: example
---

# Roadmap

Example keeps a local index of markdown notes.

## [M1] Skeleton
> outcome: The app starts and shows an empty index.
> version: 0.1.0

- [x] T1 Scaffold the app (S1)
- [x] T2 Render an empty index view (S1)

## [M2] Ingestion
> outcome: Notes from a chosen folder appear in the index.
> target: 2026-11

- [/] T3 Add folder picker (S2)
- [!] T4 Parse note front matter (S2)
  - blocked-by: T3
- [-] T5 Support Org-mode files
  - why: out of scope for v1

## Backlog
- [>] T6 Full-text search (S2)
  - from: M2
- [ ] T7 Export index as HTML

## Specs
| ID | Title | Path |
|----|-------|------|
| S1 | Architecture | docs/specs/architecture.md |
| S2 | Ingestion pipeline | docs/specs/ingestion.md |
```

`CHANGELOG.md`

```markdown
---
ptf: 1
project: example
---

# Changelog

All notable changes are documented here. Format: Keep a Changelog 1.1.0 with the
PTF extensions described in TRACKING-FORMAT.md. Versions follow SemVer.

## [Unreleased]

### Added
- Add folder picker dialog on the welcome screen (T3, S2)

### Postponed
- Postpone full-text search to backlog: the index model must stabilise first (T6)

### Abandoned
- Drop Org-mode support; only Markdown is in scope for v1 (T5)

## [0.1.0] - 2026-09-28

### Added
- Scaffold the desktop app (T1, M1)
- Render an empty index view (T2)
```

---

## 9. Authoring guidance for agents

When editing these files:

1. Read `TRACKING-FORMAT.md` (this file) and both tracking files first.
2. Never renumber or reuse IDs. New IDs are `max + 1`.
3. Change state and changelog **together** in the same commit (see 3.6).
4. Write entries for the reader of the release notes, not for the commit log:
   imperative, one sentence, no trailing period needed, reference IDs at the end.
5. When postponing, prefer moving to a concrete milestone; use `Backlog` only when
   no milestone fits.
6. When a milestone is fully done, do not delete it — its tasks are the history.
   The same applies to a phase once every milestone inside it is done.
7. Only introduce `## Phases` once milestones outnumber what fits in one glance
   (roughly 5+); small roadmaps don't need the extra layer.
8. Prefer splitting a task over nesting sub-tasks.
9. Run the invariants in section 5 mentally (or with the tool) before finishing.
