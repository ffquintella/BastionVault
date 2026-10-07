/**
 * Session Workspace layout model (T38 Phase 3, features/session-workspace.md
 * §1): tabs, each a binary split tree of panes. Pure and serialisable —
 * no React, no DOM, no Tauri — so every invariant below is unit-tested
 * against the reducer alone (`gui/src/test/sessionLayout.test.ts`).
 *
 * Invariants:
 * - A tab never holds zero panes: closing its last pane closes the tab,
 *   and closing the last tab asks for the window to close.
 * - Closing one side of a split replaces the split with the surviving
 *   side: no empty containers, no ratio drift elsewhere in the tree.
 * - Focus after closing the focused pane is deterministic: the nearest
 *   leaf of the previous sibling, else the first leaf of the next one.
 * - Every `ratio` is clamped to [0.1, 0.9]; no drag hides a pane.
 * - Zoom is presentational: it never touches the tree, so un-zoom
 *   restores the exact geometry.
 * - Pane and tab ids come from a counter in the state, so the reducer is
 *   deterministic for a given action sequence.
 * - A restore (Phase 5) lays out the saved skeleton at once, with
 *   *placeholder* panes in the exact saved shape and ratios; each is then
 *   filled in place by the session re-opened for it (same pane id, so the
 *   geometry never shifts) or closed if that open fails.
 */

import type { LayoutSaveNode, SavedLayout, SavedLayoutNode, SavedLayoutPane, SessionPlacement } from "./api";

export type PaneKind = "ssh" | "rdp" | "replay";

export interface PaneNode {
  kind: "pane";
  /** Stable pane id (layout identity). */
  id: string;
  /** Session identity — the host's key. A placeholder's is
   *  `restore:<ref>`, which names no session. */
  token: string;
  protocol: PaneKind;
  label: string;
  /** Set on a restore placeholder: what it will re-open. */
  pending?: PendingPane;
}

/** A saved pane waiting to be re-opened (Phase 5). */
export interface PendingPane {
  /** Opaque placeholder id the host echoes on the session it opens. */
  ref: string;
  resource_name: string;
  profile_id: string;
  protocol: "ssh" | "rdp";
  namespace: string;
  /** `waiting` until its turn; `opening` while its open (and any MFA
   *  prompt) runs. */
  state: "waiting" | "opening";
}

export const PLACEHOLDER_PREFIX = "restore:";

export interface SplitNode {
  kind: "split";
  /** `row` = side by side, `col` = stacked. */
  dir: "row" | "col";
  /** Share of `a`, clamped to [MIN_RATIO, MAX_RATIO]. */
  ratio: number;
  a: LayoutNode;
  b: LayoutNode;
}

export type LayoutNode = PaneNode | SplitNode;

export interface WorkspaceTab {
  id: string;
  root: LayoutNode;
  focusedPaneId: string;
  /** Set = the focused pane temporarily fills the tab. */
  zoomedPaneId?: string;
  /** Output arrived while the tab was in the background. */
  unread: boolean;
  /** A terminal bell rang while the tab was in the background. */
  bell: boolean;
}

export interface WorkspaceLayout {
  tabs: WorkspaceTab[];
  activeTabId: string | null;
  nextId: number;
  /** Set once the last tab has been closed: the window should close. */
  closeWindow: boolean;
}

export type Direction = "left" | "right" | "up" | "down";

export const MIN_RATIO = 0.1;
export const MAX_RATIO = 0.9;
export const RESIZE_STEP = 0.05;

export type LayoutAction =
  | {
      type: "place";
      session: { token: string; protocol: PaneKind; label: string };
      placement: SessionPlacement;
    }
  | { type: "closePane"; paneId: string }
  | { type: "closeTab"; tabId: string }
  | { type: "focusPane"; paneId: string }
  | { type: "focusDirection"; dir: Direction }
  | { type: "resizeFocused"; dir: Direction; step?: number }
  | { type: "setRatio"; tabId: string; path: string; ratio: number }
  | { type: "toggleZoom" }
  | { type: "activateTab"; tabId: string }
  | { type: "selectTabIndex"; index: number }
  | { type: "cycleTab"; delta: 1 | -1 }
  | { type: "moveTab"; from: number; to: number }
  | { type: "activity"; token: string; kind: "output" | "bell" }
  | { type: "restore"; layout: SavedLayout }
  | {
      type: "fillPlaceholder";
      paneRef: string;
      session: { token: string; protocol: PaneKind; label: string };
    }
  | { type: "placeholderState"; paneRef: string; state: PendingPane["state"] }
  /** Remove a placeholder whose open failed. Unlike `closePane` it never
   *  asks for the window to close: the operator needs to read why. */
  | { type: "dropPlaceholder"; paneRef: string };

export function emptyLayout(): WorkspaceLayout {
  return { tabs: [], activeTabId: null, nextId: 1, closeWindow: false };
}

export function clampRatio(ratio: number): number {
  if (!Number.isFinite(ratio)) return 0.5;
  return Math.min(MAX_RATIO, Math.max(MIN_RATIO, ratio));
}

// ── Tree helpers ────────────────────────────────────────────────────

/** Leaves in reading order (a before b). */
export function leaves(node: LayoutNode): PaneNode[] {
  return node.kind === "pane" ? [node] : [...leaves(node.a), ...leaves(node.b)];
}

/** Path of `a`/`b` steps from the root to the pane, or null. */
export function pathOf(node: LayoutNode, paneId: string, path = ""): string | null {
  if (node.kind === "pane") return node.id === paneId ? path : null;
  return pathOf(node.a, paneId, `${path}a`) ?? pathOf(node.b, paneId, `${path}b`);
}

export function nodeAt(node: LayoutNode, path: string): LayoutNode | null {
  let cur: LayoutNode = node;
  for (const step of path) {
    if (cur.kind !== "split") return null;
    cur = step === "a" ? cur.a : cur.b;
  }
  return cur;
}

function replaceAt(node: LayoutNode, path: string, replacement: LayoutNode): LayoutNode {
  if (path === "") return replacement;
  if (node.kind !== "split") return node;
  const [step, rest] = [path[0], path.slice(1)];
  return step === "a"
    ? { ...node, a: replaceAt(node.a, rest, replacement) }
    : { ...node, b: replaceAt(node.b, rest, replacement) };
}

/**
 * Remove a leaf. The split above it is replaced by the surviving side.
 * `focus` is the deterministic successor: the nearest leaf of the previous
 * sibling (its last leaf), else the first leaf of the next sibling.
 */
export function removeLeaf(
  root: LayoutNode,
  paneId: string,
): { root: LayoutNode | null; focus: string | null } {
  const path = pathOf(root, paneId);
  if (path === null) return { root, focus: null };
  if (path === "") return { root: null, focus: null };
  const parentPath = path.slice(0, -1);
  const parent = nodeAt(root, parentPath) as SplitNode;
  const side = path[path.length - 1];
  const sibling = side === "a" ? parent.b : parent.a;
  const siblingLeaves = leaves(sibling);
  const focus = side === "b" ? siblingLeaves[siblingLeaves.length - 1].id : siblingLeaves[0].id;
  return { root: replaceAt(root, parentPath, sibling), focus };
}

export interface Rect {
  x: number;
  y: number;
  w: number;
  h: number;
}

/** Each pane's rectangle in the unit square. */
export function paneRects(node: LayoutNode, rect: Rect = { x: 0, y: 0, w: 1, h: 1 }): Map<string, Rect> {
  if (node.kind === "pane") return new Map([[node.id, rect]]);
  const r = clampRatio(node.ratio);
  const [ra, rb]: [Rect, Rect] =
    node.dir === "row"
      ? [
          { x: rect.x, y: rect.y, w: rect.w * r, h: rect.h },
          { x: rect.x + rect.w * r, y: rect.y, w: rect.w * (1 - r), h: rect.h },
        ]
      : [
          { x: rect.x, y: rect.y, w: rect.w, h: rect.h * r },
          { x: rect.x, y: rect.y + rect.h * r, w: rect.w, h: rect.h * (1 - r) },
        ];
  return new Map([...paneRects(node.a, ra), ...paneRects(node.b, rb)]);
}

const EPS = 1e-9;

function overlap(a0: number, a1: number, b0: number, b1: number): number {
  return Math.max(0, Math.min(a1, b1) - Math.max(a0, b0));
}

/** The pane adjacent to `paneId` in `dir`, or null. Nearest edge first,
 *  then the largest shared border, then reading order. */
export function neighbour(root: LayoutNode, paneId: string, dir: Direction): string | null {
  const rects = paneRects(root);
  const f = rects.get(paneId);
  if (!f) return null;
  const order = leaves(root).map((l) => l.id);
  let best: { id: string; dist: number; shared: number; idx: number } | null = null;
  for (const [id, r] of rects) {
    if (id === paneId) continue;
    let dist: number;
    let shared: number;
    switch (dir) {
      case "left":
        if (r.x + r.w > f.x + EPS) continue;
        dist = f.x - (r.x + r.w);
        shared = overlap(r.y, r.y + r.h, f.y, f.y + f.h);
        break;
      case "right":
        if (r.x < f.x + f.w - EPS) continue;
        dist = r.x - (f.x + f.w);
        shared = overlap(r.y, r.y + r.h, f.y, f.y + f.h);
        break;
      case "up":
        if (r.y + r.h > f.y + EPS) continue;
        dist = f.y - (r.y + r.h);
        shared = overlap(r.x, r.x + r.w, f.x, f.x + f.w);
        break;
      case "down":
        if (r.y < f.y + f.h - EPS) continue;
        dist = r.y - (f.y + f.h);
        shared = overlap(r.x, r.x + r.w, f.x, f.x + f.w);
        break;
    }
    if (shared <= EPS) continue;
    const idx = order.indexOf(id);
    const better =
      !best ||
      dist < best.dist - EPS ||
      (Math.abs(dist - best.dist) <= EPS &&
        (shared > best.shared + EPS || (Math.abs(shared - best.shared) <= EPS && idx < best.idx)));
    if (better) best = { id, dist, shared, idx };
  }
  return best?.id ?? null;
}

// ── Selectors ───────────────────────────────────────────────────────

export function activeTab(state: WorkspaceLayout): WorkspaceTab | null {
  return state.tabs.find((t) => t.id === state.activeTabId) ?? null;
}

export function tabOfPane(state: WorkspaceLayout, paneId: string): WorkspaceTab | null {
  return state.tabs.find((t) => pathOf(t.root, paneId) !== null) ?? null;
}

export function tabOfToken(state: WorkspaceLayout, token: string): WorkspaceTab | null {
  return state.tabs.find((t) => leaves(t.root).some((l) => l.token === token)) ?? null;
}

export function paneOfToken(state: WorkspaceLayout, token: string): PaneNode | null {
  for (const t of state.tabs) {
    const hit = leaves(t.root).find((l) => l.token === token);
    if (hit) return hit;
  }
  return null;
}

export function allPanes(state: WorkspaceLayout): PaneNode[] {
  return state.tabs.flatMap((t) => leaves(t.root));
}

/** The tab's title: its focused pane's label, plus how many others share it. */
export function tabTitle(tab: WorkspaceTab): string {
  const all = leaves(tab.root);
  const focused = all.find((l) => l.id === tab.focusedPaneId) ?? all[0];
  return all.length > 1 ? `${focused.label} (+${all.length - 1})` : focused.label;
}

// ── Restore + save (Phase 5) ────────────────────────────────────────

export function isPlaceholder(pane: PaneNode): boolean {
  return pane.pending !== undefined;
}

export function placeholders(state: WorkspaceLayout): PaneNode[] {
  return allPanes(state).filter(isPlaceholder);
}

export function hasPlaceholders(state: WorkspaceLayout): boolean {
  return placeholders(state).length > 0;
}

function skeletonNode(node: LayoutNode): LayoutSaveNode | null {
  if (node.kind === "pane") {
    // Placeholders and replay panes name no live session.
    if (node.pending || node.protocol === "replay") return null;
    return { kind: "pane", token: node.token };
  }
  const a = skeletonNode(node.a);
  const b = skeletonNode(node.b);
  if (a && b) return { kind: "split", dir: node.dir, ratio: clampRatio(node.ratio), a, b };
  return a ?? b;
}

/**
 * What the workspace sends to be saved: tab order, split tree and ratios,
 * with each leaf naming its session by token (the host turns that into the
 * resource / profile / namespace it was opened from and writes nothing
 * else). Focus, zoom and unread state are not part of a layout.
 */
export function skeleton(state: WorkspaceLayout): { root: LayoutSaveNode }[] {
  const out: { root: LayoutSaveNode }[] = [];
  for (const tab of state.tabs) {
    const root = skeletonNode(tab.root);
    if (root) out.push({ root });
  }
  return out;
}

/** A stable key for "did the saved shape change". */
export function skeletonSignature(state: WorkspaceLayout): string {
  return JSON.stringify(skeleton(state));
}

export function savedPanes(layout: SavedLayout): SavedLayoutPane[] {
  const walk = (n: SavedLayoutNode): SavedLayoutPane[] => (n.kind === "pane" ? [n] : [...walk(n.a), ...walk(n.b)]);
  return layout.tabs.flatMap((t) => walk(t.root));
}

function showNamespace(ns: string): string {
  return ns === "" ? "root" : `\`${ns}\``;
}

/**
 * The cross-namespace rule, checked for the whole layout before any pane
 * is opened or any MFA prompt shown: a layout saved in another namespace
 * is refused, naming both, rather than resolving same-named resources in
 * the active one. (The host enforces the same rule again on every pane's
 * open — this is the clear, early message.)
 */
export function restoreRefusal(layout: SavedLayout, activeNamespace: string): string | null {
  const norm = (ns: string) => ns.trim().replace(/^\/+|\/+$/g, "");
  const active = norm(activeNamespace);
  const foreign = [...new Set(savedPanes(layout).map((p) => norm(p.namespace)))].filter((ns) => ns !== active);
  if (foreign.length === 0) return null;
  return (
    `This layout was saved in namespace ${foreign.map(showNamespace).join(" and ")}, but the active namespace ` +
    `is ${showNamespace(active)}. Switch to it in the main window before restoring: restoring here would open ` +
    `same-named resources in the wrong namespace.`
  );
}

// ── Reducer ─────────────────────────────────────────────────────────

function updateTab(state: WorkspaceLayout, tabId: string, f: (t: WorkspaceTab) => WorkspaceTab): WorkspaceLayout {
  return { ...state, tabs: state.tabs.map((t) => (t.id === tabId ? f(t) : t)) };
}

function activate(state: WorkspaceLayout, tabId: string): WorkspaceLayout {
  const tab = state.tabs.find((t) => t.id === tabId);
  if (!tab) return state;
  if (state.activeTabId === tabId && !tab.unread && !tab.bell) return state;
  return { ...updateTab(state, tabId, (t) => ({ ...t, unread: false, bell: false })), activeTabId: tabId };
}

function removeTab(state: WorkspaceLayout, tabId: string): WorkspaceLayout {
  const index = state.tabs.findIndex((t) => t.id === tabId);
  if (index < 0) return state;
  const tabs = state.tabs.filter((t) => t.id !== tabId);
  if (tabs.length === 0) return { ...state, tabs, activeTabId: null, closeWindow: true };
  let next: WorkspaceLayout = { ...state, tabs };
  if (state.activeTabId === tabId) {
    // The tab to the left, else the one that slid into this position.
    const neighbourTab = tabs[Math.max(0, index - 1)];
    next = activate({ ...next, activeTabId: null }, neighbourTab.id);
  }
  return next;
}

export function layoutReducer(state: WorkspaceLayout, action: LayoutAction): WorkspaceLayout {
  switch (action.type) {
    case "place": {
      if (tabOfToken(state, action.session.token)) return state;
      const pane: PaneNode = {
        kind: "pane",
        id: `p${state.nextId}`,
        token: action.session.token,
        protocol: action.session.protocol,
        label: action.session.label,
      };
      const current = activeTab(state);
      const split =
        action.placement === "workspace-split-right"
          ? "row"
          : action.placement === "workspace-split-down"
            ? "col"
            : null;
      if (split && current) {
        const targetPath = pathOf(current.root, current.focusedPaneId) ?? "";
        const target = nodeAt(current.root, targetPath)!;
        const node: SplitNode = { kind: "split", dir: split, ratio: 0.5, a: target, b: pane };
        return {
          ...updateTab(state, current.id, (t) => ({
            ...t,
            root: replaceAt(t.root, targetPath, node),
            focusedPaneId: pane.id,
            zoomedPaneId: undefined,
          })),
          nextId: state.nextId + 1,
          closeWindow: false,
        };
      }
      // A new tab — also what a split does when there is nothing to split.
      const tab: WorkspaceTab = {
        id: `t${state.nextId}`,
        root: pane,
        focusedPaneId: pane.id,
        unread: false,
        bell: false,
      };
      return {
        ...state,
        tabs: [...state.tabs, tab],
        activeTabId: tab.id,
        nextId: state.nextId + 1,
        closeWindow: false,
      };
    }

    case "closePane": {
      const tab = tabOfPane(state, action.paneId);
      if (!tab) return state;
      const { root, focus } = removeLeaf(tab.root, action.paneId);
      if (root === null) return removeTab(state, tab.id);
      return updateTab(state, tab.id, (t) => ({
        ...t,
        root,
        focusedPaneId: t.focusedPaneId === action.paneId ? (focus ?? leaves(root)[0].id) : t.focusedPaneId,
        zoomedPaneId: t.zoomedPaneId === action.paneId ? undefined : t.zoomedPaneId,
      }));
    }

    case "closeTab":
      return removeTab(state, action.tabId);

    case "focusPane": {
      const tab = tabOfPane(state, action.paneId);
      if (!tab) return state;
      const focused =
        tab.focusedPaneId === action.paneId && (!tab.zoomedPaneId || tab.zoomedPaneId === action.paneId)
          ? state
          : updateTab(state, tab.id, (t) => ({
              ...t,
              focusedPaneId: action.paneId,
              zoomedPaneId: t.zoomedPaneId && t.zoomedPaneId !== action.paneId ? undefined : t.zoomedPaneId,
            }));
      return activate(focused, tab.id);
    }

    case "focusDirection": {
      const tab = activeTab(state);
      if (!tab) return state;
      const target = neighbour(tab.root, tab.focusedPaneId, action.dir);
      if (!target) return state;
      // Moving focus leaves zoom, as in Ghostty: the target is not visible.
      return updateTab(state, tab.id, (t) => ({ ...t, focusedPaneId: target, zoomedPaneId: undefined }));
    }

    case "resizeFocused": {
      const tab = activeTab(state);
      if (!tab) return state;
      const path = pathOf(tab.root, tab.focusedPaneId);
      if (path === null) return state;
      const want = action.dir === "left" || action.dir === "right" ? "row" : "col";
      const step = (action.step ?? RESIZE_STEP) * (action.dir === "right" || action.dir === "down" ? 1 : -1);
      // Nearest ancestor split of the matching orientation.
      for (let i = path.length - 1; i >= 0; i--) {
        const splitPath = path.slice(0, i);
        const node = nodeAt(tab.root, splitPath);
        if (node?.kind === "split" && node.dir === want) {
          const ratio = clampRatio(node.ratio + step);
          if (ratio === node.ratio) return state;
          return updateTab(state, tab.id, (t) => ({ ...t, root: replaceAt(t.root, splitPath, { ...node, ratio }) }));
        }
      }
      return state;
    }

    case "setRatio": {
      const tab = state.tabs.find((t) => t.id === action.tabId);
      if (!tab) return state;
      const node = nodeAt(tab.root, action.path);
      if (node?.kind !== "split") return state;
      const ratio = clampRatio(action.ratio);
      if (ratio === node.ratio) return state;
      return updateTab(state, tab.id, (t) => ({ ...t, root: replaceAt(t.root, action.path, { ...node, ratio }) }));
    }

    case "toggleZoom": {
      const tab = activeTab(state);
      if (!tab) return state;
      if (tab.zoomedPaneId) return updateTab(state, tab.id, (t) => ({ ...t, zoomedPaneId: undefined }));
      if (tab.root.kind === "pane") return state;
      return updateTab(state, tab.id, (t) => ({ ...t, zoomedPaneId: t.focusedPaneId }));
    }

    case "activateTab":
      return activate(state, action.tabId);

    case "selectTabIndex": {
      const tab = state.tabs[action.index];
      return tab ? activate(state, tab.id) : state;
    }

    case "cycleTab": {
      if (state.tabs.length < 2) return state;
      const i = state.tabs.findIndex((t) => t.id === state.activeTabId);
      const next = (i + action.delta + state.tabs.length) % state.tabs.length;
      return activate(state, state.tabs[next].id);
    }

    case "moveTab": {
      const { from, to } = action;
      const n = state.tabs.length;
      if (from < 0 || from >= n || to < 0 || to >= n || from === to) return state;
      const tabs = [...state.tabs];
      const [moved] = tabs.splice(from, 1);
      tabs.splice(to, 0, moved);
      return { ...state, tabs };
    }

    case "activity": {
      const tab = tabOfToken(state, action.token);
      if (!tab || tab.id === state.activeTabId) return state;
      const bell = tab.bell || action.kind === "bell";
      if (tab.unread && bell === tab.bell) return state;
      return updateTab(state, tab.id, (t) => ({ ...t, unread: true, bell }));
    }

    case "restore": {
      let nextId = state.nextId;
      const build = (n: SavedLayoutNode): LayoutNode => {
        if (n.kind === "pane") {
          const ref = `r${nextId}`;
          const pane: PaneNode = {
            kind: "pane",
            id: `p${nextId}`,
            token: `${PLACEHOLDER_PREFIX}${ref}`,
            protocol: n.protocol,
            label: n.resource_name,
            pending: {
              ref,
              resource_name: n.resource_name,
              profile_id: n.profile_id,
              protocol: n.protocol,
              namespace: n.namespace,
              state: "waiting",
            },
          };
          nextId += 1;
          return pane;
        }
        return { kind: "split", dir: n.dir, ratio: clampRatio(n.ratio), a: build(n.a), b: build(n.b) };
      };
      const tabs: WorkspaceTab[] = action.layout.tabs.map((t) => {
        const root = build(t.root);
        const tab: WorkspaceTab = {
          id: `t${nextId}`,
          root,
          focusedPaneId: leaves(root)[0].id,
          unread: false,
          bell: false,
        };
        nextId += 1;
        return tab;
      });
      if (tabs.length === 0) return state;
      return {
        ...state,
        tabs: [...state.tabs, ...tabs],
        activeTabId: tabs[0].id,
        nextId,
        closeWindow: false,
      };
    }

    case "fillPlaceholder": {
      const target = allPanes(state).find((p) => p.pending?.ref === action.paneRef);
      if (!target || tabOfToken(state, action.session.token)) return state;
      const tab = tabOfPane(state, target.id)!;
      const path = pathOf(tab.root, target.id)!;
      const filled: PaneNode = {
        kind: "pane",
        id: target.id,
        token: action.session.token,
        protocol: action.session.protocol,
        label: action.session.label,
      };
      return updateTab(state, tab.id, (t) => ({ ...t, root: replaceAt(t.root, path, filled) }));
    }

    case "dropPlaceholder": {
      const target = allPanes(state).find((p) => p.pending?.ref === action.paneRef);
      if (!target) return state;
      const next = layoutReducer(state, { type: "closePane", paneId: target.id });
      return { ...next, closeWindow: state.closeWindow };
    }

    case "placeholderState": {
      const target = allPanes(state).find((p) => p.pending?.ref === action.paneRef);
      if (!target?.pending || target.pending.state === action.state) return state;
      const tab = tabOfPane(state, target.id)!;
      const path = pathOf(tab.root, target.id)!;
      const next: PaneNode = { ...target, pending: { ...target.pending, state: action.state } };
      return updateTab(state, tab.id, (t) => ({ ...t, root: replaceAt(t.root, path, next) }));
    }
  }
}
