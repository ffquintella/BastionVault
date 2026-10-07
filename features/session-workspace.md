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

**Status: Complete (T38) — Phases 0–6 implemented; none of Phases 3–6 exercised
by hand.** Sessions open as tabs and splits in one Session Workspace window by
default (`default_placement = workspace-tab`); *Separate windows* keeps one
window per session. The layout is saved as a skeleton and offered for an
explicit restore (Phase 5); a live session can move between the workspace and
a window of its own (Phase 6). Nothing from Phases 3–6 has been exercised by
hand in a running desktop build yet: the evidence is the unit and component
tests listed under each phase. The per-release manual checklist (Testing
Plan) is still open, which is why T38 stays in progress; the work this
feature still owed was split out as T108–T111. T110 — the session-only
bundle and per-window command sets — is done (§7), and so is T108 —
confirming before a session window or the workspace closes natively with
live sessions (§8); T109 and T111 remain (see *What is not yet
implemented*). Neither T110 nor T108 has been exercised by hand in a
desktop build.

What Phases 0–6 delivered:

- **Layout preference + macOS native tabs (Phase 0).** `session_workspace` in the
  GUI preferences file (`gui/src-tauri/src/preferences.rs`,
  `SessionWorkspacePrefs { layout_mode, default_placement,
  confirm_multiline_paste, chord_overrides }`, parsed strictly where used,
  validated on write by `set_session_workspace_prefs`; a file without the key
  loads as the defaults `workspace` / `workspace-tab` / paste guard on / no
  overrides). Settings → General → **Session layout**
  (`gui/src/components/SessionLayoutCard.tsx`) switches `layout_mode` and, in
  workspace mode, the default placement; in `windows` mode the own-window
  builder sets `tabbing_identifier("bv-session")` on macOS. Grouping follows the
  system's *Prefer tabs* setting or *Window → Merge All Windows* — tauri/tao set
  only the identifier, not `NSWindow.tabbingMode`. Not yet checked by hand on a
  Mac.
- **Panes (Phase 1).** `SshPane`, `RdpPane`, `ReplayPane` and the shared
  `SessionPaneHeader` in `gui/src/components/session/`; the three
  `Session*Window.tsx` routes are one-pane wrappers that read URL params, own
  the window title / `window.close()`, and send the window heartbeat.
- **Attachment registry, placement, watchdog (Phase 2).**
  `AppState::session_attachments` (`gui/src-tauri/src/session/attachments.rs`),
  the four commands in `gui/src-tauri/src/commands/session_workspace.rs`,
  `placement` on both open requests (`gui/src-tauri/src/session/workspace.rs`),
  teardown re-homed onto the registry, the orphan watchdog, and a macOS
  web-content-process hook in `lib.rs`. See §3 *Phase 2 as built*.
- **The workspace window (Phase 3).** `/workspace` route
  (`gui/src/routes/SessionWorkspaceWindow.tsx`) in the singleton
  `session-workspace` window (Phase 3 granted it the same capability as
  `ssh-*` / `rdp-*`; since T110 it has a capability and command set of its
  own, §7). Pure layout reducer
  (`gui/src/lib/sessionLayout.ts`) behind a zustand store
  (`gui/src/stores/sessionWorkspaceStore.ts`); `paneHosts` registry
  (`gui/src/lib/paneHosts.ts`); split renderer, divider and slots
  (`gui/src/components/session/workspace/SplitView.tsx`); tab strip
  (`TabStrip.tsx`). Host: `place_in_workspace` / `ensure_workspace_window` in
  `commands/connect.rs`, payload-less `session://placed`, per-event routing to
  the holding window (`gui/src-tauri/src/session/routing.rs`), and the input
  commands narrowed to the holding window. See §3 *Phase 3 as built*.
- **Keybindings + paste guard (Phase 4).** `gui/src/lib/reservedChords.ts`,
  consumed by the SSH pane's `attachCustomKeyEventHandler`, the RDP pane's
  canvas keydown filter and the workspace's capture-phase handler; the RDP
  keyboard-release chord; Settings → General → **Session keyboard & paste**
  (`gui/src/components/SessionKeyboardCard.tsx`); the multi-line paste guard
  (`gui/src/lib/pasteGuard.ts`, read per window by
  `gui/src/lib/sessionInputPrefs.ts`). See §4 *Phase 4 as built*.
- **Layout persistence + restore (Phase 5).** The workspace saves its
  layout skeleton (debounced, 1 s) through `session_layout_save`; the host
  resolves each pane's token against the attachment registry and writes only
  `{resource_name, profile_id, protocol, namespace}` per pane, per vault
  profile, to `session_layouts.json` (`gui/src-tauri/src/session/layouts.rs`).
  The layout an earlier run saved is offered — in the empty state and next
  to the tabs — as *Restore last layout (N panes)*, never applied on its
  own; each pane is re-opened through the normal connect path into a
  placeholder that holds its place in the saved shape
  (`gui/src/lib/sessionRestore.ts`). Cross-namespace restore is refused for
  the whole layout before anything opens, and again by the host on every
  pane's open. Settings → Session layout can open the workspace on its own
  and forget the saved layout. See §5 *Phase 5 as built*.
- **Moving a live session (Phase 6).** *Pop out* on a workspace pane, or
  dragging a tab out of the strip, moves the session to its own window;
  *Move to workspace* in a session's own window moves it into the workspace.
  The host hands the session straight from one window to the other
  (`session_move`, `AttachmentRegistry::transfer`) and SSH output waits —
  bounded, zeroed — for the new pane's listener handshake
  (`gui/src-tauri/src/session/output.rs`). An opt-in replay buffer
  (`session_workspace.replay_buffer`, off by default) keeps the last
  256 KiB per SSH session so a moved session redraws recent output; RDP
  drops the old window's frame channel and the new pane gets a full frame.
  See §6 *Phase 6 as built*, including the security review.
- **Phase 3–4 residuals.** Closing a pane or tab, or ⌘W, asks before it
  ends a live session; SSH panes debounce the resize they send the host
  (120 ms) so a divider drag is one `session_resize`, not a burst.
- **Session-only bundle and per-window command sets (T110).** Every window
  that renders a session or a recording loads `gui/session.html`, a second
  Vite entry that mounts only the four session routes and never fetches the
  vault token; the host has an app-command ACL, and each session window kind
  gets a capability naming exactly the commands its routes call. The main
  window keeps every command. See §7.
- **Confirm before a window closes (T108).** The native close of a
  session's own window or the workspace — close button, Alt+F4, ⌘W in a
  session's own window — asks first while a session in it is live, naming
  every session it would end. The page vetoes the close
  (`gui/src/lib/sessionWindowClose.ts`); the host stops a window's sessions
  when it is *destroyed*, not when a close is requested, and force-closes a
  window whose page does not answer a close request within 5 s
  (`gui/src-tauri/src/session/close_guard.rs`), so a hung or dead renderer
  can never trap the window or keep its sessions running. App exit stops
  every session still live. See §8.

Tests: Rust — `session::attachments` (incl. transfer and epochs),
`session::output` (bounds, zeroing, handshake replay), `session::layouts`
(skeleton, bounds, file versioning, namespace refusal), `session::workspace`,
`session::routing` (incl. epoch-gated delivery), `preferences`,
`commands::session_workspace`, `window_acl_tests` (T110: each window's
command set, checked against Tauri's own resolver), `session::close_guard`
and the T108 cases in `session::attachments::teardown_tests`. Vitest —
`gui/src/test/sessionWindowClose.test.tsx` (T108: a session's own window),
`gui/src/test/sessionBundle.test.tsx` (T110: route table, import graph,
each window's calls equal its set), `gui/src/test/sessionLayout.test.ts`
(reducer invariants, restore placeholders, skeleton, namespace refusal,
adoption by placeholder and by epoch), `reservedChords.test.ts` (chord table,
overrides, paste guard), `sessionPanes.test.tsx` (panes, incl. resize gating
and debounce, replay notice, per-pane RDP keyboard, paste guard, *Move to
workspace*), `sessionWorkspace.test.tsx` (adoption, DOM continuity, teardown,
chords, close confirmation, the window's native close, save, restore,
namespace refusal, pop-out, tear-off), `sessionLayoutCard.test.tsx` (both
Settings cards, replay opt-in, open/forget).

What is not yet implemented — split out of T38:

- ~~**T108**~~ — done: the native close of a session window or the workspace
  asks first while a session is live (§8). Not exercised by hand in a
  desktop build; added to the manual checklist.
- **T109** — replay panes in the workspace. The `replay` pane kind exists in
  the model; nothing places one. Needs a recording hand-off into the
  workspace (placement is keyed on live session tokens today) and a
  decision on whether a replay joins the saved layout.
- ~~**T110**~~ — done: the session-only bundle and per-window command sets
  (§7). Follow-ups it leaves, not tracked as tasks yet: plugin windows
  (`plugin-*`) still load the full vault UI with every command; `session.html`
  has no Content-Security-Policy (the app sets `csp: null`), so a
  compromised session realm can still `fetch` anywhere; and the workspace
  holds the resource reads its ⌘K palette and restore need
  (`list_resources`, `read_resource`, `resource_types_read`), which a
  host-side "resolve and open this saved pane" command could remove.
- **T111** — SSH output (live and replayed) over a per-webview IPC channel
  instead of `emit_to`, which Tauri 2.11 also delivers to any default-target
  `listen()` in any webview (see §3 *Phase 3 as built*). Must not reopen the
  web/RDP channel-id exposure (`session::web_rdp_conflict`).

What existed before T38:

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

#### Phase 2 as built — where it differs from the above, and why

- **The calling webview is the window.** `session_attach`, `session_detach` and
  `session_heartbeat` take no `window_label`: the host uses the label of the
  webview that made the call. A label in the request would let any window with
  IPC (a plugin window, another session's window) claim, release or keep alive
  a session rendered elsewhere. `session_attach` further accepts only the
  session's own window (`ssh-<token>` / `rdp-<token>`) or `session-workspace`;
  never `main`, `plugin-*` or `web-*`.
- **`session_list_open` is restricted** to `main` and `session-workspace`. A
  token is enough to drive a session, and today no other window can learn
  another session's token; listing must not change that.
- **Sessions are attached from birth.** The own-window path registers the
  descriptor attached to `ssh-<token>` / `rdp-<token>` *before* building the
  window, so the `CloseRequested` hook always finds it. That hook now calls
  `stop_window_sessions(label, own_token)`: every token attached to the label,
  plus the window's own token if — and only if — the registry has no entry for
  it but the session is still live (fail-safe against a registry bug). A token
  the registry knows to be elsewhere, or detached, is left alone. A window that
  fails to build now stops its session instead of leaving it dialled. (T108
  moved this hook from `CloseRequested` to `Destroyed`, behind the page's
  close veto — §8.)
- **One stop path, exactly once.** `session_close`, window close, the watchdog
  and the macOS hook all go through `attachments::stop_session` (control
  `Close` → `drop_session` → cleanup). Registry removals are atomic takes and
  `drop_session` is the atomic take of the cleanup hook, so a racing second path
  gets nothing.
- **Watchdog thresholds (60 s in the design above) are not what shipped.**
  Tick 30 s. A session is stopped when (a) its window label no longer exists
  (after a 10 s grace, so a window still being built is not judged); (b) it has
  been detached from every window for 60 s; (c) on Windows and Linux only, its
  window is shown (visible, not minimised), has heartbeated at least once, and
  has not for **180 s**. Minimised or hidden windows are never judged, and
  neither is a window that never heartbeated. Reason: WebView2 limits a hidden
  page to one timer wake-up a minute and WebKit can suspend a hidden page
  outright (tauri's `background_throttling` docs), so a 60 s threshold would
  stop live sessions whose window was merely minimised or covered.
- **macOS uses the OS signal, not heartbeats.** `tauri::Builder::
  on_web_content_process_terminate` stops every session attached to the dead
  webview's label (`reason=renderer_terminated`); heartbeat staleness is not
  judged on macOS at all, because an occluded window's page can be suspended
  with no signal to the host. Windows and Linux have no such hook in Tauri
  2.11, hence the heartbeat there.
- **Log line.** Every reap is `WARN target=audit session.reaped: token=…
  window=… reason=window_gone|heartbeat_stale|unattached|renderer_terminated
  idle_secs=…`. There is still no host-side `session.close` line for SSH/RDP
  (the spec's premise); the existing `resource-connect/{ssh,rdp}: closed
  session` info line is unchanged.
- **Workspace placements were refused, not half-built.** `resolve_placement`
  runs before anything is resolved or dialled; until Phase 3 set
  `workspace::WORKSPACE_WINDOW_AVAILABLE`, a `workspace-*` placement was
  refused, and in `windows` layout mode it is always refused.

#### Phase 3 as built — where it differs from the above, and why

- **`session://placed` carries no payload.** Tauri 2.11 delivers an
  `emit_to(label)` event to listeners in that webview *and* to every
  `listen()` registered with the default `Any` target in any webview
  (`match_any_or_filter` in tauri's `event/listener.rs`). A descriptor in the
  payload would hand every session's token to any webview that subscribes to
  the name. The event is only a wake-up: the workspace answers it (and its own
  first load, once its listener is live) with `session_list_open`, which only
  `main` and the workspace may call, and places every session attached to it
  that has no pane yet. The requested placement travels in the listing
  (`SessionDescriptor::placement`). A session placed while the window was still
  loading is therefore not lost, and its split request is still honoured.
- **`emit_to` is routing, not confidentiality.** The pumps now address SSH
  output, the closed notice and RDP resize / cursor events to the holding
  window (`session::routing::SessionEvents`, looked up per event so a session
  that changes holder follows it; a session already dropped from the registry
  falls back to its last holder so its closed notice still arrives; a detached
  one is not addressed at all). By the caveat above this is not the "strict
  narrowing" the Security section first claimed; the token remains the secret.
  A real boundary would move SSH output onto a per-webview `Channel`, as RDP
  frames already are — a follow-up, not done here.
- **Input is narrowed to the holder.** `session_input`, `session_resize`,
  `session_input_rdp_{key,mouse,wheel,resize}` and `session_attach_rdp_frames`
  take the calling webview and refuse any window but the holder
  (`attachments::authorize_input`), failing closed on an unknown token.
  `session_close` is refused only when another window holds the session
  (`authorize_close`); unknown stays a no-op success so closing twice is not an
  error. Because the session is registered attached before its window is built
  or told, the pane's handshake passes the check the moment it mounts.
- **Unreadable preferences fall back to `windows`, not to the defaults.** The
  defaults now pool sessions into the shared realm; a file the operator cannot
  read must not decide that. An absent placement opens an own window and an
  explicit `workspace-*` one is refused naming the file.
- **Window creation race.** Two opens racing to build the window: the loser's
  build fails on the duplicate label and is treated as success if the window
  now exists. A session placed into a window that is mid-close lands in a
  window that is about to vanish; the watchdog reaps it (`window_gone`) within
  one tick after `WINDOW_GONE_GRACE`.
- **Panes mount only once their host is in the document.** The portal for a
  token renders after a slot has attached its host element (`hostReady`), so
  xterm never opens on a detached node. A pane in a hidden tab measures 0×0
  and is skipped; xterm re-measures its cell when it becomes visible and the
  pane re-fits on the next frame. `session_resize` is sent only after the
  handshake (both listeners live) and then only when cols/rows change — which
  also closes a pre-existing race where a window resize could drain the
  early-bytes buffer before the listeners were live. A divider drag was not
  debounced for SSH in Phase 3; since the Phase 6 work the pane re-fits on
  every frame but sends `session_resize` only once the grid has held still
  for 120 ms (`SSH_RESIZE_DEBOUNCE_MS`), and only if it differs from what
  the host last heard. The handshake resize is never delayed. RDP keeps its
  250 ms debounce.
- **Tab title and chips.** The tab shows the focused pane's label (+ count of
  the others), a status dot and the unread / bell dot; the Rustion TTL chip
  stays in each pane header rather than on the tab.
- **Tab reorder uses pointer events**, not HTML5 drag-and-drop, which WebView2
  swallows while Tauri's file-drop handler is on.
- **Synthetic events and portals.** A pane is a portal whose React parent is
  the workspace root, so the slot's click-to-focus is a native capture
  listener; a React handler on the slot would never see the click.

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
| Prev / next tab | `⌘⇧[` / `⌘⇧]` | `Ctrl+Shift+PgUp` / `Ctrl+Shift+PgDn` (see below) |
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

#### Phase 4 as built — where it differs from the above, and why

- **Prev / next tab on Linux and Windows is `Ctrl+Shift+PgUp/PgDn`**, not
  `Ctrl+PgUp/PgDn`: the latter binds Ctrl alone, which the rule above forbids,
  and full-screen terminal programs read it (`CSI 5;5~`).
- **Chords match on `KeyboardEvent.code`** plus the four modifiers — the
  physical key, which is also what the RDP pane forwards as a scancode, and
  which does not change with Shift or Option. On a non-QWERTY layout a letter
  chord is the key in the QWERTY position.
- **What a chord may not be** (`TERMINAL_CHORDS`, `APP_CHORDS`,
  `chordProblem`): no modifier or Shift alone; Ctrl + any key that produces a
  C0 control character (letters, `[ \ ]`, Space, `2`–`8`, `-`, `/`, backquote,
  and the shifted `^@ ^^ ^_`); Alt + a letter, `.` or Backspace (readline Meta
  keys); and chords the app or OS owns (⌘K palette, ⌘C/V/X/A/Q/H/M, ⌘Tab,
  ⌘Space; Ctrl+Shift+C/V, Alt+F4, Alt+Tab). The defaults are tested against
  all of it; an override is refused in Settings before saving, and one a
  hand-edited file carries is not applied and is named (the host checks
  overrides for shape only — bounded count and length, printable ASCII — so the
  table has one owner).
- **Three consumers, one table.** The workspace window handles chords in a
  capture-phase `keydown` on `window`, so it sees them before the terminal or
  the canvas; it always calls `preventDefault` (⌘W would otherwise reach the
  native *Close Window* and close every session), and in a non-terminal text
  field it swallows the chord without running it. The panes' own filters are
  what keep a chord from the remote host in a session's own window, where no
  workspace handler exists: there a reserved chord does nothing, except that
  ⌘W still reaches the native menu and closes the window.
- **⌘T / ⌘D / ⌘⇧D open the Connect palette** with the placement the chosen
  session should get (`workspace-tab` / `-split-right` / `-split-down`); with
  no tab open a split opens a tab.
- **RDP keyboard.** The pane captures keys on its canvas, not the window; a
  click grabs the keyboard, the header says whether it is grabbed, and the
  release chord (or focus leaving the canvas) releases it. Key-ups are
  forwarded only for keys whose key-down was, and every key still held when
  the grab ends is released remotely. Known gap: on Linux and Windows a
  `Ctrl+Shift+…` chord in an RDP pane still sends the remote desktop a bare
  Ctrl / Shift press and release, because those modifiers are forwarded before
  the chord's key arrives (⌘ is never forwarded, so macOS is unaffected).
- **Paste guard.** A capture-phase `paste` listener on the terminal's container
  holds any paste containing CR or LF — including a single command with a
  trailing newline — and shows the target label, line and character counts and
  the first five lines (200 characters each). Confirm calls `term.paste`, which
  keeps bracketed-paste handling. Off only when the preference is explicitly
  `false`; an unreadable preferences file leaves it on.

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

#### Phase 5 as built — where it differs from the above, and why

- **Own file, not the preferences file.** Saved layouts live in
  `session_layouts.json` next to `preferences.json`
  (`gui/src-tauri/src/session/layouts.rs`), not as
  `SessionWorkspacePrefs::saved_layouts`. The layout is rewritten on every
  (debounced) change, and the preferences file is read-modified-written by
  many commands with no common lock, so a frequent writer there could drop a
  concurrent vault-profile edit; and `set_session_workspace_prefs` writes the
  whole struct the Settings page loaded, which would have written a stale
  layout back. The file has one writer path behind a process-wide lock, is
  written atomically (temp file + rename) and owner-only (`0600`) on Unix,
  and carries `"version": 1`: a file of any other version is refused, named,
  and left untouched, so a downgrade never destroys a newer build's layout.
  Bounds: 32 tabs, 64 panes, 16 split levels, 256-byte names without control
  characters, ratios in [0.1, 0.9] — checked on save and on read.
- **The host builds the skeleton.** The workspace sends its tree with each
  leaf naming a session by token (`session_layout_save`, workspace window
  only). The host resolves every token against the attachment registry —
  only sessions the workspace holds count — and writes `resource_name`,
  `profile_id`, `protocol` and the namespace the session was opened in. No
  token, no credential, no output reaches the file, and the frontend cannot
  write a target list the registry does not vouch for. A pane whose session
  is gone collapses its split; a save with nothing left keeps the saved
  layout rather than replacing it with an empty one.
- **Namespace per pane, vault per layout.** Each session's descriptor
  records, at the start of its open, the active namespace and the vault
  profile id the host treats as open (`last_used_id`, as the local keystore
  does). The namespace is kept per pane because one workspace can hold
  sessions opened in different namespaces (the switcher stays live). A
  layout whose sessions come from more than one vault is not saved — it has
  no single owner, and saving it under either vault would later re-open the
  other vault's resource names there — and says so.
- **Offered, never applied, and not lost to the first save.** The workspace
  reads the layout an earlier run saved once, when it opens, and holds it
  for its lifetime: the first save of this run replaces the file, but the
  earlier layout stays restorable until used, forgotten or the window
  closes. It is offered as *Restore last layout (N panes)* in the empty
  state and at the end of the tab strip (sessions often arrive before the
  operator thinks to restore). No save happens before that read lands.
  Settings → Session layout gains *Open the Session Workspace*
  (`session_workspace_open`, main window only, refused in *Separate
  windows*) so the empty state is reachable, and *Forget the saved layout*.
- **Restore = the normal open path, per pane, into placeholders.** Restore
  lays out the saved tabs, splits and ratios at once with placeholder panes,
  then re-opens them one at a time in reading order: re-read the resource
  and profile (a deleted profile, a changed protocol or a profile that needs
  a typed credential is reported, not guessed), the server-decided
  connect-time MFA gate, then `openProfileSession` → `session_open_*` with
  `placement: workspace-tab` and `restore: {namespace, pane_ref}`. The host
  echoes `pane_ref` on the session's listing and the workspace fills that
  placeholder — same pane id, so the geometry never shifts. A pane that
  fails is dropped (its split collapses; the window stays open even if it
  was the last) and named in one message. The restored shape is taken as the
  baseline, so a partial restore does not overwrite the saved layout until
  the operator changes something.
- **Cross-namespace refusal, twice.** The workspace checks the whole layout
  against the active namespace before opening anything or showing any MFA
  prompt, and refuses naming both (`restoreRefusal`). The host enforces the
  same rule on every pane's open, before the resource is read
  (`layouts::check_restore_namespace`): a namespace switched in the main
  window mid-restore cannot slip a same-named resource in. A restore is
  also refused when the open vault is not the one the layout was read for,
  and a `restore` open with an own-window placement is refused.
- **What "last layout" means.** The skeleton is saved on every change of
  shape (tab order, splits, ratios — not focus, zoom or unread state) and
  never as empty. Closing panes one by one therefore leaves the last
  non-empty shape saved; quitting with four panes open leaves four.

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

#### Phase 6 as built — where it differs from the above, and why

- **A move is a hand-off, not detach + attach.** `session_move {token, to:
  own-window | workspace}` is called by the window holding the session; the
  registry hands it straight to the destination
  (`AttachmentRegistry::transfer`), so there is no detached gap: input stays
  narrowed to exactly one window and the watchdog never sees the session
  unattached (`session_detach` is unchanged and still unused by the GUI).
  Only the holder may move a session and only to a window `attach` accepts
  (its own `ssh-`/`rdp-<token>` or `session-workspace`). Moving into the
  workspace is refused in *Separate windows* mode, like an open. The own
  window is built from the same descriptor-derived URL as at open
  (`own_window_url`); a destination that cannot be built hands the session
  back. Moving into the workspace closes the source window, whose close
  hook stops only what is still attached to it — nothing.
- **Holder epochs instead of a replay command.** Every change of holder
  bumps the session's epoch (listed as `attach_epoch`). `session_resize`
  carries the epoch it was authorised at, and the first resize a holder
  sends at an epoch is its listener handshake — every pane already sends it
  only once both listeners are live. The SSH pump delivers output only to
  the holder of the epoch that completed a handshake, through
  `SessionEvents::emit_if_epoch`, which checks the epoch and calls `emit_to`
  under the attachment lock so no transfer can slip between them. Anything
  not delivered is kept for the next handshake. So a window that has just
  been handed a session is never sent output before it listens, and one
  that gave a session up is never sent more. The workspace uses the epoch to
  tell a session moved back to it from a stale listing of a pane it closed.
- **One bounded buffer per SSH session, always; replay opt-in.** The
  pre-T38 early-bytes `Vec` (unbounded, cleared but never zeroed) is
  replaced by a fixed 256 KiB ring (`session::output`). Without the
  preference it holds only output no window has shown yet — before the
  first handshake and during a move — and is zeroed as soon as it is
  delivered; with `session_workspace.replay_buffer` it also keeps the most
  recent output after delivery, so the next holder's handshake replays it.
  A replay that starts inside a wrapped ring begins at the next line. A
  host-composed notice (never remote data) goes with a replay: what was
  dropped, or — without the preference — that earlier output is not kept.
  The preference is read at open; changing it affects sessions opened
  later.
- **RDP needs no buffer.** The move drops the old window's frame channel at
  once (`FrameSink::detach`), so no frame reaches a webview that gave the
  desktop up; the new pane attaches its own channel, which already arms a
  full-desktop repaint (`session_attach_rdp_frames` → `Repaint`). Resize and
  cursor events follow the holder as before.
- **The actions.** Workspace panes get *Pop out* (live sessions only — a
  dead session's new window would never hear its closed notice); dragging a
  tab out of the strip (released more than 48 px below it, or outside the
  window; pointer capture keeps the drag) pops out every live pane in it;
  a session's own window gets *Move to workspace* in workspace mode.

#### Security review of the output buffer (Phase 6)

The spec required this buffer to be reviewed on its own. The review, and the
mitigations as built:

| Concern | Mitigation as built |
|---|---|
| Unbounded growth (a detached session running `yes`) | Fixed 256 KiB per SSH session, allocated once at open and never reallocated; oldest bytes overwritten. The pending buffer, unbounded before, is now bounded too. |
| Plaintext left in freed memory | No growth means no un-zeroed old allocation. `clear()` zeroes the whole allocation; `Drop` zeroes it; snapshots are `Zeroizing`. The pump task owns the buffer, so it is dropped — and zeroed — when the session ends, however it ends. Pre-shell bytes are zeroed once moved in. |
| Retaining output the operator already saw | Off by default (`replay_buffer: false`); without it only not-yet-shown output is held, the same class of data the pre-T38 early buffer held. The Settings copy says the output can include secrets and that it is memory-only and wiped at close. |
| Cross-session or cross-window disclosure | Per session, owned by its pump; no command reads it. The only way out is the holder's handshake, delivered by the same epoch-gated path as live output, to the window the registry says holds the session at that epoch. |
| Persistence | Memory only. Never written to disk or logs; the saved layout carries no output. |
| Replay starting mid escape sequence | A wrapped ring is replayed from its first line break. |

Residual, stated rather than solved: the copies made to *deliver* output —
the base64 string, the serialised event, the webview's JS heap and xterm's
own scrollback — are not zeroed, exactly as for live output before this
phase; and `emit_to` is still delivered to any default-target `listen()` in
any webview, so the session token remains the confidentiality boundary for
replayed output as for live output (T111). Not exercised by hand.


### 7. Session-only bundle and per-window command sets (T110)

The Security section makes "the workspace mounts only the session routes" a
mandatory mitigation for the shared realm. Until T110 it did not hold, in two
ways: every session window loaded `index.html` — the whole vault UI, whose
root component asks the host for the operator's vault token on mount
(`bootstrapAuth` → `get_current_token`) — and the app had no ACL manifest, so
any local webview could call every app command whatever its capability said.

#### As built

- **A second page.** `gui/session.html` → `gui/src/sessionApp/main.tsx` →
  `SessionApp`: an error boundary, the toast provider and a `HashRouter`
  with four routes — `/session/ssh`, `/session/rdp`, `/workspace` (with the
  ⌘K palette) and `/session-replay` — plus a catch-all that says the window
  shows sessions only. No auth store, no session monitor, no server-info
  modal, no admin page, no `ui` barrel. It is a Vite `rolldownOptions.input`
  entry beside `index.html` and `web-chrome.html`. The host loads it for the
  workspace (`WORKSPACE_WINDOW_URL`), a session's own window
  (`own_window_url`) and a replay (`replay_window_url`), all through
  `session::workspace::SESSION_PAGE`; `App.tsx` no longer mounts the session
  routes. In a production build, none of the vault UI's page or auth-store
  code is in the chunks `session.html` loads (checked by grepping `dist/`).
- **No token in the session realm.** The ⌘K palette was armed by the auth
  store, which is why every session window fetched the token.
  `ConnectPalette` now takes an `armed` prop: the main window passes
  `isAuthenticated`; the workspace arms it outright, because the host refuses
  every command the palette calls when nobody is logged in.
- **The app has an ACL manifest.** `build.rs` reads the
  `tauri::generate_handler![…]` list in `src/lib.rs`
  (`build_support/app_commands.rs` — strict: plain paths and `//` comments
  only, anything else fails the build) and passes it to
  `tauri_build::AppManifest::commands`. From then on Tauri checks app
  commands as it does plugin commands: a webview may call one only when a
  capability matching its window or webview label grants `allow-<command>`.
  `build.rs` also writes the set `app-all-commands` — every registered
  command — to `permissions/generated/` (gitignored, like Tauri's own
  per-command files in `permissions/autogenerated/`), so a command added to
  the handler is reachable from `main` at once and from no session window
  until a set names it.
- **Per-window capabilities** (`gui/src-tauri/capabilities/`; the sets are in
  `gui/src-tauri/permissions/window-sets.json`):

  | Window | Capability | App commands | Plugin permissions |
  |---|---|---|---|
  | `main`, `plugin-*` | `default.json` | every command (`app-all-commands`) | unchanged: `core:default`, shell open, file dialogs, window drag / minimise / close / maximise / fullscreen |
  | `ssh-*`, `rdp-*` | `session-window.json` | `session-window` (16): SSH / RDP input and resize, RDP frames, close, heartbeat, move, read the session prefs, Rustion info / renew / end, and — since T108 — `session_window_closing` / `session_window_close` (§8) | `core:event:allow-listen`, `allow-unlisten` |
  | `session-workspace` | `session-workspace.json` | `session-workspace` (29): the above, plus `session_list_open`, `session_layout_save` / `_get` / `_forget`, `list_resources`, `read_resource`, `resource_types_read`, `connect_mfa_begin` / `_verify_totp` / `_verify_fido2`, `session_open_ssh` / `_rdp` / `_web` | the above; T110 also granted `core:window:allow-close`, which T108 removed (§8) |
  | `replay-*` | `session-replay.json` | `session-replay` (4): read the recording it plays | none (as before) |
  | `webchrome-*` (webview) | `web-chrome-toolbar.json` | `web_chrome_state` / `_disconnect` / `_relogin` | none (as before) |
  | `web-*` | — | none | none |

- **Decisions.**
  - *The palette stays in the workspace, web entries included.* ⌘T / ⌘D
    open it and restore re-runs the normal connect path, so the workspace
    holds the resource reads, connect-time MFA and the three
    `session_open_*` commands — each still behind the host's connect gate,
    transport tier and MFA ticket check, with no credential returned to the
    frontend. Rejected: filtering web profiles out and withholding
    `session_open_web` — the same gate, and it would have changed what the
    palette lists.
  - *No palette in a session's own window or a replay.* Those windows hold
    one session or one recording, and per-session isolation is the point of
    *Separate windows*; ⌘K there now does nothing. Rejected: giving them the
    workspace's set.
  - *Narrow by omission, never `deny-`.* Tauri 2.11's `resolve_access`
    refuses a command in every window as soon as any capability denies it,
    so a `deny-` meant for a session window would cut `main` off too.
  - *The web toolbar gets a capability.* Web Connect Phase 5 relied on the
    app having no manifest; with one, the toolbar's three commands must be
    granted. Its capability is matched by webview label only and grants no
    plugin permission, so its plugin surface stays empty and its app surface
    shrinks from every command to three.
  - *Plugin windows unchanged.* They load the full UI at
    `/plugin/<name>/…`; narrowing them needs their own bundle.
- **Tests.** `window_acl_tests` (Rust) loads the capabilities and sets and
  pins each window's app and plugin permissions; asserts that no session
  window reaches a list of sensitive commands (the token, logins, secret and
  credential reads, writes, exports, main-only session controls), that no
  capability or set uses `deny-`, and that the session windows' URLs point at
  `session.html` routes the bundle mounts; and runs Tauri's own
  `Resolved::resolve` on the exact `acl-manifests.json` / `capabilities.json`
  the build handed `generate_context!`, comparing Tauri's answer with the
  model's for every registered command and every window kind.
  `capability_isolation_tests` now lets exactly one capability reach
  `webchrome-*`. `sessionBundle.test.tsx` (vitest) pins the route table,
  walks the bundle's import graph statically (no vault page, auth store,
  `ui` barrel or shell / dialog plugin; no token or login command) and
  asserts each window's routes call exactly the commands its set grants.
- **Failure mode.** A command a session window calls without a grant is
  refused by Tauri (`Command <name> not allowed by ACL`) — an explicit error
  in that window, never a silent fallback. The vitest exists to catch that
  before it ships.
- **Not exercised by hand** in a desktop build yet; added to the manual
  checklist.

### 8. Confirm before a window closes (T108)

Closing a pane or a tab, or ⌘W inside the workspace, asked before it ended
a live session; the native close of a whole window — its close button,
Alt+F4, ⌘W in a session's own window (the macOS *Close Window* menu item)
— did not, because the host stopped every session in the window on
`WindowEvent::CloseRequested`, before any page could ask. Asking there
means letting the page veto the close, and the page is exactly what may be
dead or hung when the operator reaches for the close button. So the change
has two halves: the veto, and an escape hatch the page cannot hold shut.

#### As built

- **Teardown moved to `Destroyed`.** Both window builders install one hook
  (`commands::session_workspace::hook_session_window_close`). On
  `WindowEvent::Destroyed` it stops every session attached to the window
  (`attachments::stop_window_sessions`, with an own window's token as the
  fail-safe, unchanged); `CloseRequested` stops nothing any more. A
  regression test reads `connect.rs` and the hook and fails if a close
  request stops sessions again.
- **The page vetoes and asks.** The session bundle listens for
  `tauri://close-requested` on its own window
  (`gui/src/lib/sessionWindowClose.ts`, used by `/session/ssh`,
  `/session/rdp` and `/workspace`); while a listener is registered, Tauri
  2.11 vetoes the native close and hands the request to the page
  (`manager/window.rs`: `has_js_listener` → `prevent_close`). With nothing
  live — every session ended or errored, or the workspace is empty — the
  page closes the window at once. Otherwise it shows *Close this window?*
  naming every live session (in the workspace, read from the store, so a
  session placed while the question is open is named too), with Cancel
  focused. *Disconnect and close* closes the window; Cancel keeps it and
  every session. The window question replaces an open pane question.
  "Live" is the panes' rule: open, connecting, or not yet reported.
- **Closing goes through the host, for the calling window only.**
  `session_window_close` destroys the window that calls it; its `Destroyed`
  hook then stops the sessions. Tauri's own `onCloseRequested` is not used:
  when its handler does not veto, it calls `destroy()`, which needs
  `core:window:allow-destroy` — and the window plugin resolves its `label`
  argument against every window, so that grant would let a session page
  destroy `main` or another session's window (stopping its sessions without
  asking). For the same reason the workspace loses the
  `core:window:allow-close` T110 gave it (it closed itself through it when
  its last tab closed); it now uses `session_window_close` there and for
  ⌘W with no tab. No session window has a `core:window` permission.
- **The escape hatch** (`session::close_guard`, state
  `AppState::session_close_guard`). The `CloseRequested` hook records the
  request synchronously and arms a timer. The page must answer within
  `CLOSE_ANSWER_TIMEOUT` (5 s) — `session_window_closing`, sent only once
  its question has rendered (so a page that cannot render it does not
  answer), or `session_window_close`. Unanswered, the host logs
  `WARN target=audit session.window_force_closed: window=… reason=close_unanswered waited_ms=…`,
  stops the window's sessions (`session.reaped: … reason=close_unanswered`)
  and destroys the window; if it cannot be destroyed, the sessions are
  stopped all the same. A second click while a request is pending joins it
  rather than restarting the clock, so clicking repeatedly on a hung window
  cannot postpone the forced close. Request ids are unique across window
  lifetimes and `Destroyed` forgets the window, so a timer from a window
  that has since been rebuilt under the same label (a pop-out after a
  move) cannot force the new one. A close the page does not veto (no
  listener yet, or a route without one) closes natively and the timer
  finds the request forgotten.
- **Why the escape hatch is needed.** Tauri 2.11 never drops a dead
  renderer's JS listeners (`event/listener.rs` removes them only on an
  explicit `unlisten`), so after a renderer death every later close of
  that window is vetoed with nothing to answer it. On macOS the
  web-content-process hook now also marks the window, and its next close
  is forced at once (`reason=renderer_terminated`) instead of after the
  timeout. On Windows and Linux the timeout covers it; the heartbeat
  watchdog still stops the sessions of a dead renderer on its own.
- **Answers are bound to the caller.** Both commands take the window from
  the calling webview, refuse any window that does not render sessions
  (`close_guard::renders_sessions`: the workspace and `ssh-` / `rdp-`
  windows) and any webview that is not its window's main webview. No
  webview can answer — and so suppress the forced close — for another
  window. Any webview with `core:event:allow-listen` can register a
  close-request listener targeting another window, making Tauri veto that
  window's close; the forced close still fires, because only the window
  itself can answer.
- **A move destroys its source window.** `session_move` into the workspace
  used to `close()` the session's old window; that close would now reach
  its page, which would ask about a session that is no longer its. The host
  destroys it instead; its `Destroyed` hook stops nothing, the session being
  attached to the workspace.
- **App exit stops what is left.** Closing the last window exits the app
  from inside that window's `Destroyed` event, so the teardown the event
  spawned would race the process exit — slightly worse than when teardown
  ran on the close request. `RunEvent::Exit` now stops every SSH/RDP
  session still live (`attachments::stop_all_sessions`: the registry's and
  any live one it lost) and waits for window teardowns already running,
  within 3 s, so the LDAP library check-in still runs; past the budget it
  logs `session.exit_teardown_incomplete`. The connections themselves die
  with the process either way. This also covers ⌘Q, which closes no window.
- **Decisions.**
  - *The page asks, not the host.* As the roadmap note specified: the
    confirmation matches the pane and tab confirmations, names sessions by
    the panes' own status (the host cannot tell an SSH session the remote
    ended from a live one — its entry stays until a close), and is
    unit-tested in vitest. Rejected: a host-owned native dialog
    (`tauri-plugin-dialog`) on `CloseRequested`, which keeps the page out of
    the decision entirely. Its cost is the one residual below.
  - *5 s, not longer.* The page answers after one render and one IPC round
    trip. Erring short costs the confirmation for a page too busy to answer
    — the window closes as it did before T108; erring long leaves a hung
    window unclosable for longer.
- **Residual, stated.** A page that answers but never closes — a
  compromised renderer — can now keep its own window, and the sessions in
  it, open through a close attempt, where before the close request stopped
  them whatever the page did. It already drives those sessions; quitting
  the app still stops them. Not exercised by hand in a desktop build; added
  to the manual checklist. Quitting the app (⌘Q, the main window's Quit)
  still does not ask.

## Phases

| Phase | Scope | Status |
|---|---|---|
| 0 | macOS native window tabbing + layout-mode preference | **Complete** (not yet checked by hand on a Mac) |
| 1 | Pane extraction | **Complete** |
| 2 | Attachment registry + placement + watchdog | **Complete** (thresholds differ from §3; see *Phase 2 as built*) |
| 3 | The workspace window | **Complete** (not yet exercised by hand; see §3 *Phase 3 as built*) |
| 4 | Keybindings + paste guard | **Complete** (not yet exercised by hand; see §4 *Phase 4 as built*) |
| 5 | Layout persistence + restore | **Complete** (not yet exercised by hand; see §5 *Phase 5 as built*) |
| 6 | Detach / move between windows | **Complete** (not yet exercised by hand; see §6 *Phase 6 as built*) |
| 7 | Deferred | — |

### Phase 0 — macOS native window tabbing — **Complete**

One builder line (`tabbing_identifier`) behind the `layout_mode = "windows"`
preference, plus the Settings toggle. Delivers stacking on macOS immediately,
with today's per-session webview isolation fully intact and effectively zero
risk. Ships independently of everything below.

As built: Settings → General → Session layout; `SESSION_TABBING_IDENTIFIER`
in `session/workspace.rs`. Grouping follows the macOS *Prefer tabs* setting
(or *Window → Merge All Windows*); forcing `tabbingMode = preferred` would need
an `unsafe` AppKit call and was left out.

### Phase 1 — pane extraction — **Complete**

`SshPane` / `RdpPane` / `ReplayPane` extracted from the three
`Session*Window.tsx` routes; routes become one-pane wrappers that read URL params
and render the pane. Pure refactor: same DOM, same handshake order, same close
semantics. Vitest coverage for the panes lands here.

As built: `gui/src/components/session/`. Two window-scoped behaviours were
kept as they were, and Phase 3 must change them before a window hosts more
than one pane: `SshPane` fits on `window` resize only (a divider drag needs a
`ResizeObserver` on the pane), and `RdpPane` captures keys on `window` (keys
must go to the focused pane only). Both were changed in Phase 3.

### Phase 2 — attachment registry + placement + watchdog — **Complete**

`session_attachments` on `AppState`; `session_list_open` / `session_attach` /
`session_detach` / `session_heartbeat`; `placement` on both open requests;
teardown re-homed onto the attachment with the orphan watchdog. Still no
workspace UI — `own-window` remains the default until Phase 3 lands, so this
phase is observable only through the new commands and the watchdog log line.

As built: see §3 *Phase 2 as built*.

### Phase 3 — the workspace window — **Complete**

`/workspace` route, `sessionWorkspaceStore` + reducer, tab strip, split tree
renderer, `paneHosts` registry, divider drag, zoom, per-pane chrome, tab
reorder, bell / unread dot. `default_placement` flips to `workspace-tab`.

Host work Phase 2 left for this phase: flip
`workspace::WORKSPACE_WINDOW_AVAILABLE` (and `validate_prefs` with it); add
`session-workspace` to the `windows` list in
`gui/src-tauri/capabilities/default.json` (today the label has no IPC at all)
and keep `capability_isolation_tests` green; ensure the singleton window at
`index.html#/workspace`, register the session attached to
`session-workspace` before emitting, and send `session://placed` with
`emit_to(WORKSPACE_WINDOW_LABEL, …)` rather than a global `emit`; heartbeat
from the workspace window with `useSessionHeartbeat`; hook its
`CloseRequested` to `close_window_sessions(label, None, WindowClose)`.

As built: all of the above, plus the Phase 2 carry-overs (`SshPane` fits with a
`ResizeObserver` on its own box; `RdpPane` captures keys on its canvas; the
input commands and the pumps' events go to the holding window). Departures in
§3 *Phase 3 as built*.

### Phase 4 — keybindings + paste guard — **Complete**

`reservedChords.ts`, the SSH `attachCustomKeyEventHandler` filter, the RDP
keydown filter, the RDP keyboard-release chord, the Settings chord list with
override + conflict detection, multi-line paste confirmation.

As built: all of the above; departures in §4 *Phase 4 as built*.

### Phase 5 — layout persistence + restore — **Complete**

`SessionWorkspacePrefs`, save-on-change (debounced), the empty-state restore
action, per-pane reconnect through the normal open path, cross-namespace refusal.

As built: all of the above, with the layouts in their own versioned file
rather than `SessionWorkspacePrefs`; departures in §5 *Phase 5 as built*.

### Phase 6 — detach / move between windows — **Complete**

Bounded per-session output ring + replay-on-attach for SSH, full-frame refresh
for RDP, "Move to new window" / "Move to workspace" pane actions, drag a tab out
of the strip. Gated on its own security review of the output buffer.

As built: all of the above (the "Move to new window" action is labelled *Pop
out*); the security review and the departures are in §6 *Phase 6 as built*.

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
  API surface beyond the `session_*` commands) — **met by T110** (§7): it
  loads `session.html`, which mounts only the session routes and never
  fetches the vault token, and it can call only its own command set — the
  `session_*` commands plus the connect path its palette and restore use
  (resource reads, connect-time MFA), nothing that reads a secret or a
  credential; session bytes are never
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
  T108 moved the window half once more — from the close *request* to the
  window's destruction, behind a page veto — and added the escape hatch that
  force-closes a window whose page does not answer, plus a stop-everything
  pass at app exit (§8). The residual it leaves: a compromised page can keep
  its own window and sessions open through a close attempt.
- **Credentials are unaffected.** No credential material crosses into the
  frontend in any phase; placement changes where a session is *rendered*, never
  how it is *resolved*. Every open still goes through the same resolver, connect
  gate, transport tier and MFA ticket check.
- **Event scoping can be tightened once attachment exists.** `app.emit` is
  global, so any webview that knows a token's event names can subscribe.
  Phase 3 moved the pumps to `emit_to(holder)`, landing with the
  attach-before-handshake ordering (attach → subscribe → `session_resize` →
  early-bytes drain). It is **not** the strict narrowing this bullet first
  claimed: Tauri 2.11 also delivers an `emit_to` event to any `listen()`
  registered with the default `Any` target, in any webview. The token stays the
  secret — it reaches only `main`, the rendering window and (by
  `session_list_open`) the workspace — and `session://placed` carries none.
  What Phase 3 did make strict is *input*: only the holding window may drive a
  session (§3 *Phase 3 as built*).
- **One keystroke can now reach the wrong host.** Six visible panes make
  mis-targeted input materially more likely than six overlapping windows did.
  Countermeasures are UX, and they are in scope for that reason: a clearly
  focused pane border, the target `user@host` in every pane's header (not just
  the tab), the multi-line paste guard on by default, and no broadcast input.
- **Persisted layouts are a target list.** `session_layouts.json` records which
  hosts an operator connects to and which profiles they use — inventory
  metadata in a local file (owner-only on Unix), not secrets, but worth
  stating: no tokens, no credentials, no session output is persisted — the
  host writes it from its own registry, not from what the frontend sends —
  and restore always re-authorises through the live connect path (including
  MFA) rather than resuming anything.
- **Cross-namespace restore fails closed.** Each saved pane carries the
  namespace it was opened in; restoring it elsewhere is refused — by the
  workspace for the whole layout, and by the host on every pane's open —
  rather than silently resolving same-named resources in the active
  namespace.
- **Phase 6's output ring is the one new plaintext store.** Bounded, per-session,
  memory-only, zeroed and dropped with the session, opt-in, and reviewed on its
  own — see §6 *Security review of the output buffer*. Session output contains
  whatever the operator printed.

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
  naming both namespaces (`sessionLayout.test.ts`, `sessionWorkspace.test.tsx`;
  the host's per-pane check in `session::layouts`).
- Restore keeps the saved shape and ratios, goes through the MFA gate and
  `session_open_*` per pane with the `restore` context, drops a pane it
  cannot open with the reason, and is not saved back as a change.
- Save: the skeleton names sessions by token only and is debounced; focus
  and unread state are not part of it.
- Move: *Pop out* and tear-off call `session_move` and never `session_close`;
  a stale listing does not resurrect a moved pane, a later epoch re-adopts it.
- Window close (T108; `sessionWindowClose.test.tsx`, `sessionWorkspace.test.tsx`):
  the window takes over its close request only when it has a session; with
  a live session it asks, naming every one, and answers the host only once
  the question is on screen; Cancel keeps everything; *Disconnect and
  close* calls `session_window_close` (no window named) and never
  `session_close` or the window plugin; nothing live closes at once without
  answering; every repeated request is answered; the window question
  replaces a pane question; a refused close is reported; unmounting stops
  listening.

### Rust unit tests (`cargo nextest run -p bastion-vault-gui --lib`)

- Attachment registry: attach → detach → re-attach; a second attach while a live
  window holds the token is refused; `drop_session` clears the attachment.
- Teardown fan-out: closing a window label with three attached tokens closes all
  three and runs each `SessionCleanup` exactly once.
- Watchdog: an attachment starved of heartbeats past the threshold is reaped;
  one that keeps heartbeating is not; a reap runs the same cleanup path as a
  clean close.
- Output buffer (`session::output`): bounded, keeps the newest bytes in order,
  zeroes on clear; handshake replay with and without the opt-in ring; an
  undelivered handshake changes nothing.
- Layouts (`session::layouts`): skeleton from tokens with no token in the
  output, collapse of unknown tokens, two-vault refusal, bounds, file
  round-trip with `0600`, another format version refused and left untouched.
- Transfer and epochs (`session::attachments`), epoch-gated delivery
  (`session::routing`).
- Close guard (T108, `session::close_guard`): an answered request is never
  forced; an unanswered one is forced exactly once; repeated requests do not
  postpone it; a request after an answer is new; a destroyed window is
  forgotten and a rebuilt one under the same label is not forced by the old
  timer; a dead renderer is forced at once; answers are per window. Teardown
  (`session::attachments::teardown_tests`): a forced close followed by the
  `Destroyed` hook stops each session once; destroying a move's source
  window stops nothing; app exit stops every live session, registered or
  lost, once. `commands::session_workspace`: no window builder stops
  sessions on a close request. `window_acl_tests`: the two close commands in
  the session sets, and no `core:window` permission — close or destroy — in
  any session window, checked against Tauri's resolver.
- Placement: `own-window` builds a window (existing behaviour, unchanged);
  `workspace-tab` builds no per-session window and emits `session://placed`.
  (`session::workspace` tests placement resolution — absent → the preference
  default, strict parsing, `windows`-mode refusals. The window-building half
  needs a Tauri runtime and has no unit test; the registry side — registered
  attached before the window, listing carries the placement, input and close
  authorisation, event routing — is tested in `session::attachments` and
  `session::routing`, and the workspace's side in `sessionWorkspace.test.tsx`.)

### Integration / manual

- Cucumber: open two SSH sessions into one workspace as tabs; split the second
  tab and open a third session into the split; close the last pane of a tab and
  see the tab go; close the workspace and verify both sessions produced a
  `session.close` audit line.
- Manual checklist (documented, per release, like the existing RDP checklist):
  an RDP pane in a 50/50 split negotiates the reduced geometry and re-negotiates
  on divider drag; the RDP keyboard-release chord works; macOS native tabs group
  in `windows` mode; with the per-window command sets (T110), an SSH and an RDP
  session each work in their own window and in the workspace (input, resize,
  Disconnect, *Move to workspace*, *Pop out*), ⌘T opens the palette and
  connects, an MFA-gated profile prompts, *Restore last layout* re-opens
  panes, a recording replays — and no window's console shows `not allowed by
  ACL`. T108, on each platform: the close button, Alt+F4 and (macOS) ⌘W on
  a session's own window and on the workspace ask while a session is live,
  Cancel keeps it, *Disconnect and close* ends it with one
  `window destroyed → session drop` line per session (and an LDAP library
  account checked back in); a window whose session has ended closes at
  once; *Move to workspace* closes the old window without asking; closing
  the workspace's last tab closes it; a renderer killed from the OS
  (Activity Monitor / Task Manager) leaves a window that closes on the
  first click within 5 s with `session.window_force_closed`; closing the
  last window with a live LDAP-library session still checks the account in.
- Regression: the whole existing Resource Connect suite runs unchanged against
  `placement = own-window`.

## Tracking

When phases land, update [CHANGELOG.md](../CHANGELOG.md) (the isolation
trade-off goes under **Security**), [ROADMAP.md](../ROADMAP.md), this file's
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
