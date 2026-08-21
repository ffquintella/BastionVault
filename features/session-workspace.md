# Feature: Session Workspace — tabbed + split session layout

## Summary

Today every Resource Connect session gets its own free-floating OS window. Open
four hosts and the operator is managing four overlapping windows by hand. This
feature gives the session surface the layout model a terminal emulator has:

- **Tabs** — sessions stack in one **Session Workspace** window with a tab strip,
  each tab carrying a title, a live status chip and the Rustion TTL chip.
- **Splits** — any tab can be split horizontally / vertically into a binary pane
  tree (Ghostty / tmux semantics): split, focus-move, resize by dragging the
  divider, zoom a pane, close a pane.
- **Keyboard-first** — Ghostty-style default chords (`⌘T` / `⌘D` / `⌘⇧D` /
  `⌘⌥→` / `⌘1..9` / `⌘⇧↵`, `Ctrl+Shift+…` on Linux and Windows), with a single
  reserved-chord table so a chord can never be captured by the workspace in one
  pane type and silently forwarded to the remote host in another.
- **Native window tabs (macOS)** — a cheaper, isolation-preserving alternative
  for operators who want stacking without a shared webview: keep one
  `WebviewWindow` per session and group them with the OS's own tab bar.

Both SSH panes (xterm.js) and RDP panes (canvas) participate; the recording
replay window joins as a third pane kind. Layout state is persisted as a
*skeleton* (resource + profile references, never tokens, never credentials) so a
workspace can be re-opened deliberately after a restart, re-running the full
connect path — including connect-time MFA — for every pane.

Builds directly on [features/resource-connect.md](resource-connect.md) (shipped,
Phases 1–7) and [features/connect-mfa-and-fido2-ssh.md](connect-mfa-and-fido2-ssh.md).
No server-side change: this is entirely GUI host + frontend.

## Motivation

- **Window management is the operator's job today, and it should not be.** A
  bastion operator working an incident routinely holds 3–8 sessions at once
  (app host, db host, the bastion itself, a jump target). The current model —
  `WebviewWindowBuilder … .inner_size(900.0, 540.0)` per session
  ([gui/src-tauri/src/commands/connect.rs:399](../gui/src-tauri/src/commands/connect.rs:399))
  — spawns each one centred and overlapping the last. Every comparable tool
  (Ghostty, iTerm2, Windows Terminal, Teleport Connect, Termius, Royal TS)
  solved this with tabs + splits years ago; the absence reads as an unfinished
  product, and it is the single most visible piece of session-UX debt we carry.
- **Side-by-side is a real workflow, not a nicety.** Tailing a log on one host
  while restarting a service on another is the normal shape of the work. Doing it
  today means manually tiling two 900×540 windows on every incident.
- **The plumbing is already layout-agnostic.** Sessions are keyed by an opaque
  token in `AppState::connect_sessions`
  ([gui/src-tauri/src/state.rs:191](../gui/src-tauri/src/state.rs:191)), and PTY
  bytes are delivered by *global* `app.emit` on per-session event names
  ([gui/src-tauri/src/session/ssh.rs:371](../gui/src-tauri/src/session/ssh.rs:371)).
  Any webview that knows the token and the event names can drive the session. The
  only thing genuinely bound to "one window per session" is the teardown hook
  (`WindowEvent::CloseRequested` → `drop_session`) and the URL-param handoff. Both
  are small, and both are the risky parts — hence the phasing below.
- **RDP already resizes dynamically.** `SessionRdpWindow` debounces a
  `ResizeObserver` into `session_input_rdp_resize` and re-allocates on the
  server-confirmed `resize` event, so an RDP pane in a split behaves correctly
  without new protocol work.

## Current State

**Status: Todo.** Nothing in this document is implemented; it is the design for
the work.

What exists today:

- `session_open_ssh` / `session_open_rdp` each build a dedicated
  `WebviewWindow` labelled `ssh-<token>` / `rdp-<token>`, pass
  `(token, stdout/frame event, closed event, label)` as URL params into a
  `HashRouter` fragment, and hook `CloseRequested` to run
  `send_control(Close)` → `drop_session` → `run_cleanup`
  ([connect.rs:399](../gui/src-tauri/src/commands/connect.rs:399),
  [connect.rs:721](../gui/src-tauri/src/commands/connect.rs:721)).
- [gui/src/routes/SessionSshWindow.tsx](../gui/src/routes/SessionSshWindow.tsx)
  (261 lines) owns *both* the xterm wiring and the whole window chrome
  (title, status pill, error text, `RustionSessionChip`, Disconnect button).
  [SessionRdpWindow.tsx](../gui/src/routes/SessionRdpWindow.tsx) (410) and
  [SessionReplayWindow.tsx](../gui/src/routes/SessionReplayWindow.tsx) (410) have
  the same shape.
- The frontend never learns a session's identity except through the URL params
  it was spawned with. There is no "list my live sessions" command, and no
  window↔session mapping on the host side.
- The first `session_resize` doubles as the "frontend listener is live"
  handshake that drains the host's early-bytes buffer
  ([ssh.rs:440](../gui/src-tauri/src/session/ssh.rs:440)). There is no
  scrollback retained host-side after that flush, so a frontend that re-mounts
  loses everything already written.
- Callers: the Connect button on the resource Connection tab
  ([ResourcesPage.tsx:647](../gui/src/routes/ResourcesPage.tsx:647),
  [:1639](../gui/src/routes/ResourcesPage.tsx:1639)) and the ⌘K palette
  ([ConnectPalette.tsx:236](../gui/src/components/ConnectPalette.tsx:236)).
  Both just call `api.sessionOpenSsh` / `sessionOpenRdp` and let the host place
  the window.

## Scope

### In scope

- **Pane extraction.** `SshPane` / `RdpPane` / `ReplayPane` presentational
  components taking props (token, event names, label, protocol metadata), with
  the existing `/session/*` routes reduced to thin one-pane wrappers. No
  behaviour change in that slice.
- **Session Workspace window** — a new `/workspace` route in its own
  `WebviewWindow` (label `session-workspace`), hosting a tab strip and, per tab,
  a binary split tree of panes.
- **Placement** — `session_open_{ssh,rdp}` accept a `placement` field
  (`workspace-tab` | `workspace-split-right` | `workspace-split-down` |
  `own-window`), defaulting from a GUI preference. Existing callers keep working
  unchanged (absent field = preference default).
- **Host-side attachment registry** — which window currently owns which session
  token, so teardown is exact: workspace close → close every attached session;
  pane close → close one; orphaned session (webview died without
  `CloseRequested`) → reaped by a heartbeat watchdog.
- **Session inventory command** — `session_list_open` returning a descriptor per
  live session so a workspace can enumerate and (re)claim sessions instead of
  depending on URL params.
- **Layout interactions** — split right / split down, focus move by direction,
  divider drag with ratio clamping, pane zoom (temporarily fill the tab), close
  pane, close tab, reorder tabs by drag, `⌘1..9` tab select, next/prev tab.
- **Per-pane chrome** — status pill (`connecting` / `open` / `closed` / `error`),
  `RustionSessionChip` (renew + TTL, already a shared component), Disconnect,
  and a focused-pane border. Tab title = the session label, with a bell /
  unread-output dot for background panes.
- **Reserved-chord table** — one exported table consumed by both the SSH pane's
  `attachCustomKeyEventHandler` and the RDP pane's keydown filter, plus an
  operator-visible list in Settings and a documented "release keyboard" chord for
  RDP panes that grab everything.
- **Multi-line paste guard** — pasting text containing a newline into a terminal
  pane asks for confirmation first (default on, preference to disable). Cheap
  insurance that gets much more valuable once one keystroke can reach the wrong
  of six visible prod shells.
- **macOS native window tabbing** — `tabbing_identifier("bv-session")` on the
  per-session window builder when the operator chooses the `windows` layout mode,
  so stacking is available *without* a shared webview realm (macOS only; verified
  present in tauri 2.11.5,
  `WebviewWindowBuilder::tabbing_identifier`, `#[cfg(target_os = "macos")]`).
- **Layout persistence + explicit restore** — skeleton only (tab/split shape,
  ratios, `{resource_name, profile_id, protocol}` per pane, vault profile id,
  namespace). Restore is an operator action, never automatic, and re-runs the
  normal connect path per pane.
- **Detach / re-attach a live session between windows** (Phase 6) — requires a
  bounded host-side output buffer; see Design and Security.

### Out of scope (explicit)

- **Broadcast / synchronised input across panes.** Typing one command into six
  production shells at once is exactly the accident this product exists to make
  harder. If it is ever built it needs an explicit arming toggle, a persistent
  banner in every receiving pane, a per-pane audit event, and its own feature
  file. Not here.
- **Embedding session panes inside the main application window.** The current
  isolation property — "a compromise of the resources list page can't reach into
  a running session window's memory"
  ([resource-connect.md](resource-connect.md), Security Considerations) — is
  worth keeping. The workspace is a separate window whose bundle mounts only the
  session routes.
- **Tiling beyond a binary tree** (arbitrary grids, floating panes, tab groups
  per resource group). Binary splits cover the workflow; grids can be layered on
  later without changing the model's storage shape.
- **Per-pane session recording UI.** Recording is Rustion's
  ([features/rustion-integration.md](rustion-integration.md)); the workspace
  shows the existing chip and nothing more.
- **Cross-machine / cross-vault workspaces.** A layout belongs to one vault
  profile and one namespace.
- **Terminal features that are not layout** — scrollback search, hyperlink
  detection, image protocols, font/theme editor. Separate, smaller changes.
- **Server-side state.** Nothing about layout reaches the vault. No new logical
  paths, no `v2/` routes, no audit schema change (see Security for the one
  audit-adjacent behaviour that *does* change: teardown ownership).

## Design

### 1. Layout model

A pure, serialisable binary tree per tab. Kept in a zustand store
(`gui/src/stores/sessionWorkspaceStore.ts`, matching the existing store
convention) with a reducer that is unit-testable without React:

```ts
export type PaneKind = "ssh" | "rdp" | "replay";

export interface PaneNode {
  kind: "pane";
  id: string;            // stable pane id (layout identity)
  token: string;         // session identity — the host's key
  protocol: PaneKind;
  label: string;
}

export interface SplitNode {
  kind: "split";
  dir: "row" | "col";    // row = side-by-side, col = stacked
  ratio: number;         // 0.1 … 0.9, clamped
  a: LayoutNode;
  b: LayoutNode;
}

export type LayoutNode = PaneNode | SplitNode;

export interface WorkspaceTab {
  id: string;
  root: LayoutNode;
  focusedPaneId: string;
  zoomedPaneId?: string; // set = focused pane temporarily fills the tab
}
```

Reducer invariants, each with a test:

- A tab never ends with zero panes: closing the last pane in a tab closes the
  tab; closing the last tab closes the workspace window.
- Closing one side of a split replaces the split with the surviving side
  (no empty containers, no ratio drift).
- Focus after a close moves to the nearest sibling in the tree, deterministically
  (previous sibling, else parent's other subtree's first leaf).
- `ratio` clamped to `[0.1, 0.9]`; a divider drag cannot make a pane
  unreachable.
- Zoom is presentational only — it never mutates the tree, so un-zoom always
  restores the exact prior geometry.

### 2. DOM continuity — the one hard frontend constraint

An xterm.js instance loses its screen and scrollback when its container is
unmounted, and an RDP `<canvas>` loses its backing store. React's reconciler
unmounts a subtree when it moves to a different parent — which is precisely what
"drag this tab into a split" does. So the pane's *content* must not be owned by
the React tree that lays it out.

The pattern: a module-level registry of long-lived host elements.

```ts
// gui/src/lib/paneHosts.ts
const hosts = new Map<string, HTMLDivElement>();   // token → host element

export function paneHost(token: string): HTMLDivElement {
  let el = hosts.get(token);
  if (!el) {
    el = document.createElement("div");
    el.className = "h-full w-full min-w-0";
    hosts.set(token, el);
  }
  return el;
}

export function releasePaneHost(token: string): void { … }   // on session close
```

The layout renderer's leaf component owns an empty slot `<div>` and, in a layout
effect, `appendChild`s the token's host element into it. Moving a pane between
splits, tabs or positions moves one DOM node — the xterm instance, its scrollback
and its event subscriptions are untouched. Background tabs are `display: none`
on the tab container rather than unmounted, and on re-show the pane re-runs
`fit.fit()` and fires `session_resize` **only if** cols/rows actually changed
(the RDP pane equivalently skips the debounced resize when dimensions match, as
it already does).

This is the single most important implementation rule in the feature; a naive
React port of the current window components will look correct in a screenshot
and lose every operator's scrollback on the first split.

### 3. Host-side: attachment, placement, teardown

New state on `AppState`:

```rust
/// token → window label currently rendering the session. Written by
/// `session_attach`, cleared by `session_detach` / `drop_session`.
pub session_attachments: tokio::sync::Mutex<HashMap<String, Attachment>>,

pub struct Attachment {
    pub window_label: String,
    /// Last heartbeat from the rendering webview. A webview that dies
    /// without `CloseRequested` (crash, OOM) stops heartbeating; the
    /// watchdog closes the session so we never leak a live PTY with no
    /// paired `session.close`.
    pub last_seen: std::time::Instant,
}
```

New commands (`gui/src-tauri/src/commands/connect.rs`, mirrored in
`gui/src/lib/api.ts`):

| Command | Purpose |
|---|---|
| `session_list_open` | Descriptor per live session: `token`, `protocol`, `label`, `resource_name`, `profile_id`, event names, RDP geometry, `opened_at`, `attached_to` |
| `session_attach { token, window_label }` | Claim a session for a window; refuses if another *live* window holds it |
| `session_detach { token }` | Release without closing (the move-between-windows path) |
| `session_heartbeat { window_label }` | Liveness for the watchdog; one call per workspace per 15 s, not per pane |

`SshOpenRequest` / `RdpOpenRequest` gain:

```rust
/// Where the session should be rendered. Absent = the GUI preference
/// default (`workspace-tab` unless the operator chose window mode).
#[serde(default)]
pub placement: Option<Placement>,
```

For a `workspace-*` placement the host does **not** build a per-session window.
It ensures the singleton `session-workspace` window exists (creating it at
`index.html#/workspace` if not, and focusing it if so), then emits
`session://placed` carrying the descriptor + the requested placement. The
workspace's reducer creates the tab or the split and mounts the pane, which
attaches and then performs the existing handshake — the pane must be listening
*before* it calls `session_resize`, exactly as today, because that first resize
is what drains the early-bytes buffer.

Teardown moves from "the spawning window's close hook" to the attachment:

- Pane close → `session_close` (exists today) → `drop_session` + `run_cleanup`,
  and clears the attachment.
- Workspace window `CloseRequested` → for every token attached to that label,
  the same path. Preserves the LDAP library check-in
  (`SessionCleanupKind::LdapLibraryCheckIn`) that today rides the per-window
  hook.
- Watchdog task (60 s tick): any attachment whose `last_seen` is older than
  60 s is torn down and logged at WARN with the window label. This closes a hole
  that exists *today* in a different form — a killed webview process that never
  emits `CloseRequested` currently leaks the session until the app exits.

`own-window` placement keeps the current code path verbatim, so the whole
existing surface (including every integration test that drives it) stays valid.

### 4. Keybindings

Defaults, matching Ghostty where Ghostty has an opinion:

| Action | macOS | Linux / Windows |
|---|---|---|
| New tab (opens the ⌘K Connect palette in the workspace) | `⌘T` | `Ctrl+Shift+T` |
| Close pane (tab if last pane) | `⌘W` | `Ctrl+Shift+W` |
| Split right / down | `⌘D` / `⌘⇧D` | `Ctrl+Shift+E` / `Ctrl+Shift+O` |
| Move focus | `⌘⌥` + arrow | `Ctrl+Shift` + arrow |
| Resize focused divider | `⌘⌃` + arrow | `Ctrl+Alt` + arrow |
| Zoom / un-zoom pane | `⌘⇧↵` | `Ctrl+Shift+Enter` |
| Select tab 1–9 | `⌘1`…`⌘9` | `Alt+1`…`Alt+9` |
| Prev / next tab | `⌘⇧[` / `⌘⇧]` | `Ctrl+PgUp` / `Ctrl+PgDn` |
| Release keyboard grab (RDP panes) | `⌘⌥⌃K` | `Ctrl+Alt+Shift+K` |

`Ctrl` alone is never bound: it belongs to the remote shell. On Linux and
Windows the modifier is `Ctrl+Shift`, which is what every terminal there uses,
for the same reason.

One table, two consumers:

```ts
// gui/src/lib/reservedChords.ts — the only place a workspace chord is defined.
export const RESERVED_CHORDS: ReservedChord[] = [ … ];
export function matchChord(e: KeyboardEvent): WorkspaceAction | null { … }
```

The SSH pane installs `term.attachCustomKeyEventHandler(e => matchChord(e) === null)`
so xterm forwards everything except the reserved set; the RDP pane's keydown
handler consults `matchChord` before forwarding scancodes. Deriving both from one
table is what prevents the failure mode where a chord works in a terminal pane
and gets typed into a Windows desktop instead. A vitest asserts that no reserved
chord collides with a C0 control character an operator would need
(`Ctrl+C`, `Ctrl+D`, `Ctrl+Z`, `Ctrl+[`, …) and that every declared action has a
binding on both platforms.

### 5. Persistence

Stored in the GUI preferences file (`gui/src-tauri/src/preferences.rs`, the same
place `PasswordPolicy` lives — a UX policy, not an authorization one):

```rust
pub struct SessionWorkspacePrefs {
    /// `workspace` (default) or `windows`. `windows` keeps one
    /// WebviewWindow per session; on macOS they group as native tabs.
    pub layout_mode: String,
    pub default_placement: String,
    pub confirm_multiline_paste: bool,   // default true
    pub chord_overrides: HashMap<String, String>,
    /// Last layout skeleton, per vault profile id.
    pub saved_layouts: HashMap<String, SavedLayout>,
}
```

`SavedLayout` holds the tab/split shape, ratios, and per pane
`{resource_name, profile_id, protocol}` plus the `namespace` the layout was built
in. It holds **no token, no credential, no session output**. Restore is an
explicit "Restore last layout (4 panes)" action in the workspace's empty state;
it walks the panes and calls the normal open path for each, which means the
connect gate, the transport tier and connect-time MFA all apply per pane exactly
as if the operator had clicked Connect. Restoring a layout whose recorded
namespace differs from the active one is refused with a clear message rather than
resolving same-named resources in the current namespace — the same class of bug
as the namespace credential split already fixed in the Rustion path.

### 6. Detach / move between windows (Phase 6)

Within one webview, a pane moves as a DOM node and keeps its scrollback. Across
webviews it cannot: the receiving pane starts with an empty xterm and the host
has already discarded everything past the early-bytes flush. Making detach honest
therefore needs a bounded host-side output ring per SSH session (proposal: 256
KiB, dropped with the session) that a fresh attach replays before going live. For
RDP the equivalent is cheaper and stateless — request a full-frame refresh on
attach, which the pump already knows how to emit.

That buffer is new plaintext-of-session-output living in host RAM, and session
output routinely contains secrets the operator printed. It gets its own security
review, it is opt-in, and it is deliberately the last phase rather than folded
into the layout work.

## Phases

### Phase 0 — macOS native window tabbing — **Todo**

One builder line (`tabbing_identifier`) behind the `layout_mode = "windows"`
preference, plus the Settings toggle. Delivers stacking on macOS immediately,
with today's per-session webview isolation fully intact and effectively zero
risk. Ships independently of everything below.

### Phase 1 — pane extraction — **Todo**

`SshPane` / `RdpPane` / `ReplayPane` extracted from the three
`Session*Window.tsx` routes; routes become one-pane wrappers that read URL params
and render the pane. Pure refactor: same DOM, same handshake order, same close
semantics. Vitest coverage for the panes lands here.

### Phase 2 — attachment registry + placement + watchdog — **Todo**

`session_attachments` on `AppState`; `session_list_open` / `session_attach` /
`session_detach` / `session_heartbeat`; `placement` on both open requests;
teardown re-homed onto the attachment with the orphan watchdog. Still no
workspace UI — `own-window` remains the default until Phase 3 lands, so this
phase is observable only through the new commands and the watchdog log line.

### Phase 3 — the workspace window — **Todo**

`/workspace` route, `sessionWorkspaceStore` + reducer, tab strip, split tree
renderer, `paneHosts` registry, divider drag, zoom, per-pane chrome, tab
reorder, bell / unread dot. `default_placement` flips to `workspace-tab`.

### Phase 4 — keybindings + paste guard — **Todo**

`reservedChords.ts`, the SSH `attachCustomKeyEventHandler` filter, the RDP
keydown filter, the RDP keyboard-release chord, the Settings chord list with
override + conflict detection, multi-line paste confirmation.

### Phase 5 — layout persistence + restore — **Todo**

`SessionWorkspacePrefs`, save-on-change (debounced), the empty-state restore
action, per-pane reconnect through the normal open path, cross-namespace refusal.

### Phase 6 — detach / move between windows — **Todo**

Bounded per-session output ring + replay-on-attach for SSH, full-frame refresh
for RDP, "Move to new window" / "Move to workspace" pane actions, drag a tab out
of the strip. Gated on its own security review of the output buffer.

### Phase 7 — deferred

- Synchronised / broadcast input (needs arming UI + per-pane audit; see Scope).
- Arbitrary grid tiling, tab groups keyed to resource groups or asset groups.
- Scrollback search and export.
- Session-workspace layouts shared between operators (a layout is a target list;
  sharing one is closer to a saved query than to a preference, and belongs with
  [features/asset-groups.md](asset-groups.md)).

## Dependencies

No new Rust crates. No new npm dependencies: the split tree, tab strip and
divider drag are ~400 lines of local code against the Tailwind 4 tokens the GUI
already uses.

Deliberately *not* adding a layout library. `react-mosaic`, `dockview` and
`golden-layout` all unmount a panel's subtree when it moves, which is exactly the
behaviour §2 exists to avoid; they also bring their own CSS systems and 60–150 KB
to fight with Tailwind 4. The tree we need is 60 lines of reducer.

## Security Considerations

- **Shared JS realm is a real reduction in isolation, and it is the price of
  splits.** Today each session is a separate `WebviewWindow` with its own
  context; a workspace puts N panes in one realm, so a renderer compromise in one
  pane can read another pane's terminal buffer. Mitigations, all mandatory:
  the workspace window mounts only the session routes (no admin pages, no vault
  API surface beyond the `session_*` commands); session bytes are never
  interpolated into HTML (xterm writes to its own DOM/canvas, RDP to a canvas —
  no `innerHTML` of remote data anywhere in a pane); and the `layout_mode =
  "windows"` preference (Phase 0) keeps per-session isolation available, with
  macOS native tabs providing stacking at that setting. This trade-off gets an
  explicit line in the CHANGELOG under **Security**, not a silent default flip.
- **Teardown must stay exact, because a missing `session.close` is an audit
  signal.** Moving teardown off `WindowEvent::CloseRequested` and onto the
  attachment registry is the highest-risk change in the feature: a bug there
  leaks a live PTY (and, for the LDAP library source, an un-checked-in account).
  Hence: pane close, tab close, window close and *webview death* all converge on
  the same `drop_session` + `run_cleanup` path, the watchdog covers the death
  case that has no hook today, and the reaper logs at WARN with the window label.
- **Credentials are unaffected.** No credential material crosses into the
  frontend in any phase; placement changes where a session is *rendered*, never
  how it is *resolved*. Every open still goes through the same resolver, connect
  gate, transport tier and MFA ticket check.
- **Event scoping can be tightened once attachment exists.** `app.emit` is
  global today, so any webview that knows a token's event names can subscribe.
  With an authoritative attachment we can move to `emit_to(window_label)` — a
  strict narrowing. It must land *with* the attach-before-handshake ordering
  (attach → subscribe → `session_resize` → early-bytes drain), or the buffer
  flushes to a window that is not listening yet.
- **One keystroke can now reach the wrong host.** Six visible panes make
  mis-targeted input materially more likely than six overlapping windows did.
  Countermeasures are UX, and they are in scope for that reason: a clearly
  focused pane border, the target `user@host` in every pane's header (not just
  the tab), the multi-line paste guard on by default, and no broadcast input.
- **Persisted layouts are a target list.** `saved_layouts` records which hosts an
  operator connects to and which profiles they use — inventory metadata in a
  local preferences file, not secrets, but worth stating: no tokens, no
  credentials, no session output is persisted, and restore always re-authorises
  through the live connect path (including MFA) rather than resuming anything.
- **Cross-namespace restore fails closed.** A layout carries the namespace it was
  built in; restoring it elsewhere is refused rather than silently resolving
  same-named resources in the active namespace.
- **Phase 6's output ring is the one new plaintext store.** Bounded, per-session,
  memory-only, dropped with the session, opt-in, and reviewed on its own. Session
  output contains whatever the operator printed.

## Testing Plan

### Unit tests (vitest, `gui/src/**/*.test.tsx`)

- Layout reducer: split right / down produces the expected tree; closing one side
  collapses the split; closing the last pane closes the tab; closing the last tab
  signals window close; focus-after-close is deterministic; ratio clamping;
  zoom is non-destructive (zoom → un-zoom is identity on the tree).
- `paneHosts`: the host element for a token is identity-stable across a re-render
  that moves the pane between splits and between tabs; `releasePaneHost` is
  called exactly once per closed session.
- Pane re-show: hiding and re-showing a tab fires `session_resize` only when
  cols/rows changed.
- `reservedChords`: every action has a macOS and a non-macOS binding; no reserved
  chord shadows a terminal control character; `matchChord` returns `null` for
  plain typing, `Ctrl+C`, `Ctrl+D`, `Ctrl+Z`.
- Paste guard: single-line paste passes through; text containing `\n` prompts.
- Restore: a layout with a foreign namespace is refused, with the message
  naming both namespaces.

### Rust unit tests (`cargo nextest run -p bastion-vault-gui --lib`)

- Attachment registry: attach → detach → re-attach; a second attach while a live
  window holds the token is refused; `drop_session` clears the attachment.
- Teardown fan-out: closing a window label with three attached tokens closes all
  three and runs each `SessionCleanup` exactly once.
- Watchdog: an attachment starved of heartbeats past the threshold is reaped;
  one that keeps heartbeating is not; a reap runs the same cleanup path as a
  clean close.
- Placement: `own-window` builds a window (existing behaviour, unchanged);
  `workspace-tab` builds no per-session window and emits `session://placed`.

### Integration / manual

- Cucumber: open two SSH sessions into one workspace as tabs; split the second
  tab and open a third session into the split; close the last pane of a tab and
  see the tab go; close the workspace and verify both sessions produced a
  `session.close` audit line.
- Manual checklist (documented, per release, like the existing RDP checklist):
  an RDP pane in a 50/50 split negotiates the reduced geometry and re-negotiates
  on divider drag; the RDP keyboard-release chord works; macOS native tabs group
  in `windows` mode.
- Regression: the whole existing Resource Connect suite runs unchanged against
  `placement = own-window`.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md) (the isolation
trade-off goes under **Security**), [roadmap.md](../roadmap.md), this file's
"Current State", and the Connect section of [docs/api.md](../docs/api.md) if the
new Tauri commands get documented alongside the existing `session_*` set.

## Notes on alternatives considered

- **One Tauri webview per pane (`unstable` multi-webview), splits done by the
  OS.** This is the option that *keeps* per-session isolation while still giving
  real splits, and it is the honest long-term answer if the shared-realm concern
  ever outweighs the ergonomics. Rejected for now: the API is behind tauri's
  `unstable` feature flag (`tauri 2.11.5`, `webview/mod.rs`), each webview is a
  separate WebKit / WebView2 process so eight panes means eight processes on an
  operator laptop, and there are no tab-strip or divider primitives — we would
  write the same layout code *plus* native positioning glue. Revisit when the
  API stabilises.
- **macOS native window tabbing only.** Cheap, isolation-preserving, and shipped
  as Phase 0 for exactly that reason — but macOS-only and no splits, so it
  answers "stack these windows" and not "put these two side by side".
- **Session panes as a tab inside the main app window.** Rejected: it puts the
  admin surface and live sessions in one realm, which is the isolation property
  [resource-connect.md](resource-connect.md) deliberately bought.
- **A layout library (`react-mosaic` / `dockview` / `golden-layout`).** Rejected
  on the unmount-on-move behaviour that would silently destroy scrollback,
  plus bundle size and CSS conflict. See Dependencies.
- **Keeping one window per session and adding a window-manager panel** ("your 6
  sessions" list with raise/tile buttons). Cheaper than the workspace, but it
  automates window arrangement rather than replacing it — the operator still
  lives in six OS windows, and tiling via OS APIs is unreliable across the three
  platforms we ship.
- **Reusing the terminal multiplexer on the target host** (`tmux` / `screen`).
  Not a substitute: it needs a multiplexer installed on every target, only
  splits panes that share one host, and puts the layout on the far side of the
  bastion where our audit trail and our UI cannot see it.
