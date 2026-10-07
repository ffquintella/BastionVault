/**
 * T38 Phase 3 — the Session Workspace layout reducer
 * (features/session-workspace.md §1 invariants).
 */

import { describe, it, expect } from "vitest";

import {
  MAX_RATIO,
  MIN_RATIO,
  emptyLayout,
  layoutReducer,
  leaves,
  neighbour,
  tabTitle,
  hasPlaceholders,
  placeholders,
  restoreRefusal,
  savedPanes,
  skeleton,
  type LayoutAction,
  type LayoutNode,
  type WorkspaceLayout,
} from "../lib/sessionLayout";
import type { OpenSessionListing, SavedLayout, SessionPlacement } from "../lib/api";
import { useSessionWorkspaceStore } from "../stores/sessionWorkspaceStore";

function place(state: WorkspaceLayout, token: string, placement: SessionPlacement = "workspace-tab") {
  return layoutReducer(state, {
    type: "place",
    session: { token, protocol: "ssh", label: `ssh op@${token}:22` },
    placement,
  });
}

function run(state: WorkspaceLayout, ...actions: LayoutAction[]): WorkspaceLayout {
  return actions.reduce(layoutReducer, state);
}

/** Compact shape: `t1` for a pane, `[row a|b]` / `[col a/b]` for splits. */
function shape(node: LayoutNode): string {
  if (node.kind === "pane") return node.token;
  return node.dir === "row" ? `[${shape(node.a)}|${shape(node.b)}]` : `[${shape(node.a)}/${shape(node.b)}]`;
}

function paneId(state: WorkspaceLayout, token: string): string {
  for (const t of state.tabs) {
    const hit = leaves(t.root).find((l) => l.token === token);
    if (hit) return hit.id;
  }
  throw new Error(`no pane for ${token}`);
}

describe("placing sessions", () => {
  it("a tab placement opens a new, active tab", () => {
    const s = place(place(emptyLayout(), "A"), "B");
    expect(s.tabs.map((t) => shape(t.root))).toEqual(["A", "B"]);
    expect(s.activeTabId).toBe(s.tabs[1].id);
    expect(s.tabs[1].focusedPaneId).toBe(paneId(s, "B"));
  });

  it("split right / down split the focused pane and focus the new one", () => {
    let s = place(emptyLayout(), "A");
    s = place(s, "B", "workspace-split-right");
    expect(shape(s.tabs[0].root)).toBe("[A|B]");
    expect(s.tabs[0].focusedPaneId).toBe(paneId(s, "B"));
    s = place(s, "C", "workspace-split-down");
    expect(shape(s.tabs[0].root)).toBe("[A|[B/C]]");
    expect(s.tabs[0].focusedPaneId).toBe(paneId(s, "C"));
    expect(s.tabs).toHaveLength(1);
  });

  it("a split with nothing to split opens a tab", () => {
    const s = place(emptyLayout(), "A", "workspace-split-right");
    expect(s.tabs).toHaveLength(1);
    expect(shape(s.tabs[0].root)).toBe("A");
  });

  it("placing a token twice is a no-op (one pane per session)", () => {
    const s = place(emptyLayout(), "A");
    expect(place(s, "A")).toBe(s);
    expect(place(s, "A", "workspace-split-right")).toBe(s);
  });

  it("ids are deterministic for a given action sequence", () => {
    const a = place(place(emptyLayout(), "A"), "B", "workspace-split-right");
    const b = place(place(emptyLayout(), "A"), "B", "workspace-split-right");
    expect(a).toEqual(b);
  });
});

describe("closing", () => {
  it("closing one side of a split collapses it to the survivor, ratios elsewhere untouched", () => {
    let s = place(emptyLayout(), "A");
    s = place(s, "B", "workspace-split-right");
    s = place(s, "C", "workspace-split-down");
    s = run(s, { type: "setRatio", tabId: s.tabs[0].id, path: "", ratio: 0.3 });
    s = run(s, { type: "closePane", paneId: paneId(s, "C") });
    expect(shape(s.tabs[0].root)).toBe("[A|B]");
    expect(s.tabs[0].root.kind === "split" && s.tabs[0].root.ratio).toBe(0.3);
  });

  it("focus after a close is the previous sibling's nearest leaf, else the next sibling's first", () => {
    let s = place(emptyLayout(), "A");
    s = place(s, "B", "workspace-split-right"); // [A|B]
    s = run(s, { type: "focusPane", paneId: paneId(s, "A") });
    s = place(s, "C", "workspace-split-down"); // [[A/C]|B], focus C
    // C is a `b` child: the previous sibling is A.
    s = run(s, { type: "closePane", paneId: paneId(s, "C") });
    expect(s.tabs[0].focusedPaneId).toBe(paneId(s, "A"));

    // A is an `a` child: no previous sibling, so the other subtree's first leaf.
    let t = place(emptyLayout(), "A");
    t = place(t, "B", "workspace-split-right");
    t = run(t, { type: "focusPane", paneId: paneId(t, "B") });
    t = place(t, "C", "workspace-split-down"); // [A|[B/C]]
    t = run(t, { type: "focusPane", paneId: paneId(t, "A") });
    t = run(t, { type: "closePane", paneId: paneId(t, "A") });
    expect(shape(t.tabs[0].root)).toBe("[B/C]");
    expect(t.tabs[0].focusedPaneId).toBe(paneId(t, "B"));

    // Closing an unfocused pane leaves focus where it is.
    let u = place(emptyLayout(), "A");
    u = place(u, "B", "workspace-split-right");
    u = run(u, { type: "closePane", paneId: paneId(u, "A") });
    expect(u.tabs[0].focusedPaneId).toBe(paneId(u, "B"));
  });

  it("closing the last pane closes the tab; closing the last tab asks for the window to close", () => {
    let s = place(place(emptyLayout(), "A"), "B");
    s = run(s, { type: "closePane", paneId: paneId(s, "B") });
    expect(s.tabs.map((t) => shape(t.root))).toEqual(["A"]);
    expect(s.activeTabId).toBe(s.tabs[0].id);
    expect(s.closeWindow).toBe(false);
    s = run(s, { type: "closeTab", tabId: s.tabs[0].id });
    expect(s.tabs).toEqual([]);
    expect(s.activeTabId).toBeNull();
    expect(s.closeWindow).toBe(true);
  });

  it("closing the active tab activates its left neighbour, else the next", () => {
    let s = place(place(place(emptyLayout(), "A"), "B"), "C");
    s = run(s, { type: "selectTabIndex", index: 1 });
    s = run(s, { type: "closeTab", tabId: s.tabs[1].id });
    expect(tabTitle(s.tabs.find((t) => t.id === s.activeTabId)!)).toContain("A");
    s = run(s, { type: "selectTabIndex", index: 0 });
    s = run(s, { type: "closeTab", tabId: s.tabs[0].id });
    expect(tabTitle(s.tabs.find((t) => t.id === s.activeTabId)!)).toContain("C");
  });

  it("an empty workspace is not a closed one", () => {
    expect(emptyLayout().closeWindow).toBe(false);
  });
});

describe("ratios", () => {
  it("are clamped to [0.1, 0.9], whatever a drag reports", () => {
    let s = place(place(emptyLayout(), "A"), "B", "workspace-split-right");
    const tabId = s.tabs[0].id;
    for (const [input, want] of [
      [-3, MIN_RATIO],
      [0, MIN_RATIO],
      [0.05, MIN_RATIO],
      [0.42, 0.42],
      [0.95, MAX_RATIO],
      [7, MAX_RATIO],
      [Number.NaN, 0.5],
    ] as const) {
      s = run(s, { type: "setRatio", tabId, path: "", ratio: input });
      const root = s.tabs[0].root;
      expect(root.kind === "split" && root.ratio).toBe(want);
    }
  });

  it("the resize chord moves the nearest split of the matching orientation", () => {
    let s = place(emptyLayout(), "A");
    s = place(s, "B", "workspace-split-right");
    s = place(s, "C", "workspace-split-down"); // [A|[B/C]], focus C
    s = run(s, { type: "resizeFocused", dir: "left" });
    const root = s.tabs[0].root;
    expect(root.kind === "split" && root.ratio).toBeCloseTo(0.45);
    s = run(s, { type: "resizeFocused", dir: "down" });
    const inner = s.tabs[0].root.kind === "split" ? s.tabs[0].root.b : null;
    expect(inner?.kind === "split" && inner.ratio).toBeCloseTo(0.55);
    // Clamped at the edge, and a no-op past it.
    for (let i = 0; i < 20; i++) s = run(s, { type: "resizeFocused", dir: "left" });
    const clamped = s.tabs[0].root;
    expect(clamped.kind === "split" && clamped.ratio).toBe(MIN_RATIO);
    expect(run(s, { type: "resizeFocused", dir: "left" })).toBe(s);
  });
});

describe("zoom", () => {
  it("is presentational: zoom → un-zoom is the identity on the tree", () => {
    let s = place(emptyLayout(), "A");
    s = place(s, "B", "workspace-split-right");
    s = place(s, "C", "workspace-split-down");
    s = run(s, { type: "setRatio", tabId: s.tabs[0].id, path: "", ratio: 0.33 });
    const before = s.tabs[0].root;
    const zoomed = run(s, { type: "toggleZoom" });
    expect(zoomed.tabs[0].zoomedPaneId).toBe(paneId(s, "C"));
    expect(zoomed.tabs[0].root).toBe(before);
    const back = run(zoomed, { type: "toggleZoom" });
    expect(back.tabs[0].zoomedPaneId).toBeUndefined();
    expect(back.tabs[0].root).toBe(before);
  });

  it("does nothing on a single pane, and moving focus leaves it", () => {
    const one = place(emptyLayout(), "A");
    expect(run(one, { type: "toggleZoom" })).toBe(one);
    let s = place(one, "B", "workspace-split-right");
    s = run(s, { type: "toggleZoom" }, { type: "focusDirection", dir: "left" });
    expect(s.tabs[0].zoomedPaneId).toBeUndefined();
    expect(s.tabs[0].focusedPaneId).toBe(paneId(s, "A"));
  });
});

describe("focus by direction", () => {
  it("moves to the adjacent pane, preferring the larger shared border", () => {
    let s = place(emptyLayout(), "A");
    s = place(s, "B", "workspace-split-right");
    s = place(s, "C", "workspace-split-down"); // A left; B top-right; C bottom-right
    const root = s.tabs[0].root;
    expect(neighbour(root, paneId(s, "C"), "up")).toBe(paneId(s, "B"));
    expect(neighbour(root, paneId(s, "C"), "left")).toBe(paneId(s, "A"));
    expect(neighbour(root, paneId(s, "B"), "left")).toBe(paneId(s, "A"));
    // From A, B and C share equal borders: reading order breaks the tie.
    expect(neighbour(root, paneId(s, "A"), "right")).toBe(paneId(s, "B"));
    expect(neighbour(root, paneId(s, "A"), "left")).toBeNull();
    expect(run(s, { type: "focusDirection", dir: "down" })).toBe(s);
  });
});

describe("tabs", () => {
  it("select by index, cycle with wrap-around, reorder", () => {
    let s = place(place(place(emptyLayout(), "A"), "B"), "C");
    s = run(s, { type: "selectTabIndex", index: 0 });
    expect(s.activeTabId).toBe(s.tabs[0].id);
    expect(run(s, { type: "selectTabIndex", index: 8 })).toBe(s);
    s = run(s, { type: "cycleTab", delta: -1 });
    expect(s.activeTabId).toBe(s.tabs[2].id);
    s = run(s, { type: "cycleTab", delta: 1 });
    expect(s.activeTabId).toBe(s.tabs[0].id);
    const active = s.activeTabId;
    s = run(s, { type: "moveTab", from: 0, to: 2 });
    expect(s.tabs.map((t) => shape(t.root))).toEqual(["B", "C", "A"]);
    expect(s.activeTabId).toBe(active);
    expect(run(s, { type: "moveTab", from: 0, to: 9 })).toBe(s);
  });

  it("output or a bell in a background tab marks it until it is shown", () => {
    let s = place(place(emptyLayout(), "A"), "B"); // B active
    expect(run(s, { type: "activity", token: "B", kind: "output" })).toBe(s);
    s = run(s, { type: "activity", token: "A", kind: "output" });
    expect(s.tabs[0]).toMatchObject({ unread: true, bell: false });
    // Repeated output changes nothing (no re-render per chunk).
    expect(run(s, { type: "activity", token: "A", kind: "output" })).toBe(s);
    s = run(s, { type: "activity", token: "A", kind: "bell" });
    expect(s.tabs[0]).toMatchObject({ unread: true, bell: true });
    s = run(s, { type: "activateTab", tabId: s.tabs[0].id });
    expect(s.tabs[0]).toMatchObject({ unread: false, bell: false });
  });

  it("the title is the focused pane's label, with the count of the others", () => {
    let s = place(emptyLayout(), "A");
    expect(tabTitle(s.tabs[0])).toBe("ssh op@A:22");
    s = place(s, "B", "workspace-split-right");
    expect(tabTitle(s.tabs[0])).toBe("ssh op@B:22 (+1)");
  });
});

// ── Phase 5: restore placeholders, the saved skeleton, the namespace rule ──

const SAVED: SavedLayout = {
  saved_at: "t",
  tabs: [
    {
      root: {
        kind: "split",
        dir: "col",
        ratio: 0.25,
        a: { kind: "pane", resource_name: "web01", profile_id: "cp", protocol: "ssh", namespace: "" },
        b: {
          kind: "split",
          dir: "row",
          ratio: 0.7,
          a: { kind: "pane", resource_name: "db01", profile_id: "cp", protocol: "ssh", namespace: "" },
          b: { kind: "pane", resource_name: "win01", profile_id: "cp", protocol: "rdp", namespace: "" },
        },
      },
    },
    { root: { kind: "pane", resource_name: "bastion", profile_id: "cp", protocol: "ssh", namespace: "" } },
  ],
};

describe("restore + save (Phase 5)", () => {
  it("lays out the saved shape at once, with ratios, as placeholders", () => {
    const s = run(emptyLayout(), { type: "restore", layout: SAVED });
    expect(s.tabs).toHaveLength(2);
    const root = s.tabs[0].root;
    expect(root.kind === "split" && root.dir === "col" && root.ratio).toBe(0.25);
    const ph = placeholders(s);
    expect(ph.map((p) => p.pending!.resource_name)).toEqual(["web01", "db01", "win01", "bastion"]);
    expect(ph.every((p) => p.token.startsWith("restore:"))).toBe(true);
    expect(new Set(ph.map((p) => p.pending!.ref)).size).toBe(4);
    expect(hasPlaceholders(s)).toBe(true);
    // Nothing to save while placeholders stand.
    expect(skeleton(s)).toEqual([]);
    expect(s.activeTabId).toBe(s.tabs[0].id);
  });

  it("fills a placeholder in place: same pane id, same geometry", () => {
    let s = run(emptyLayout(), { type: "restore", layout: SAVED });
    const db = placeholders(s)[1];
    const idsBefore = leaves(s.tabs[0].root).map((l) => l.id);
    s = run(s, {
      type: "fillPlaceholder",
      paneRef: db.pending!.ref,
      session: { token: "sess_db", protocol: "ssh", label: "ssh op@db01:22" },
    });
    const filled = leaves(s.tabs[0].root).find((l) => l.token === "sess_db")!;
    expect(filled.id).toBe(db.id);
    expect(filled.pending).toBeUndefined();
    expect(placeholders(s)).toHaveLength(3);
    // Only the leaf changed: same panes in the same places, same ratios.
    expect(leaves(s.tabs[0].root).map((l) => l.id)).toEqual(idsBefore);
    const root = s.tabs[0].root;
    expect(root.kind === "split" && root.ratio).toBe(0.25);
    expect(root.kind === "split" && root.b.kind === "split" && root.b.ratio).toBe(0.7);
    // Unknown refs and tokens already placed change nothing.
    expect(run(s, { type: "fillPlaceholder", paneRef: "nope", session: { token: "x", protocol: "ssh", label: "x" } })).toBe(s);
  });

  it("dropping a failed placeholder never closes the window", () => {
    let s = run(emptyLayout(), {
      type: "restore",
      layout: { saved_at: "", tabs: [SAVED.tabs[1]] },
    });
    s = run(s, { type: "dropPlaceholder", paneRef: placeholders(s)[0].pending!.ref });
    expect(s.tabs).toHaveLength(0);
    expect(s.closeWindow).toBe(false);
  });

  it("the skeleton is tab order, splits and ratios by token — not focus, zoom or unread", () => {
    let s = place(place(emptyLayout(), "A"), "B", "workspace-split-right");
    s = place(s, "C");
    const sk = skeleton(s);
    expect(sk).toEqual([
      {
        root: { kind: "split", dir: "row", ratio: 0.5, a: { kind: "pane", token: "A" }, b: { kind: "pane", token: "B" } },
      },
      { root: { kind: "pane", token: "C" } },
    ]);
    const moved = run(s, { type: "focusDirection", dir: "left" }, { type: "activity", token: "A", kind: "bell" });
    expect(skeleton(moved)).toEqual(sk);
  });

  it("refuses a layout from another namespace, naming both; root reads as root", () => {
    const inTenant: SavedLayout = {
      saved_at: "",
      tabs: [{ root: { kind: "pane", resource_name: "web01", profile_id: "cp", protocol: "ssh", namespace: "tenant-a" } }],
    };
    expect(restoreRefusal(inTenant, "tenant-a")).toBeNull();
    expect(restoreRefusal(inTenant, "/tenant-a/")).toBeNull();
    const refusal = restoreRefusal(inTenant, "tenant-b")!;
    expect(refusal).toContain("`tenant-a`");
    expect(refusal).toContain("`tenant-b`");
    expect(restoreRefusal(inTenant, "")).toContain("root");
    expect(restoreRefusal(SAVED, "")).toBeNull();
    expect(savedPanes(SAVED)).toHaveLength(4);
  });
});

describe("workspace store adoption (Phases 5–6)", () => {
  function listing(token: string, extra: Partial<OpenSessionListing> = {}): OpenSessionListing {
    return {
      token,
      protocol: "ssh",
      label: `ssh op@${token}:22`,
      resource_name: token,
      profile_id: "cp",
      stdout_event: `o-${token}`,
      closed_event: `c-${token}`,
      resize_event: null,
      cursor_event: null,
      width: null,
      height: null,
      opened_at: "2026-10-07T00:00:00Z",
      placement: "workspace-tab",
      pane_ref: null,
      attached_to: "session-workspace",
      attach_epoch: 1,
      ...extra,
    };
  }

  it("a session naming a placeholder fills it instead of opening a tab", () => {
    const store = useSessionWorkspaceStore.getState();
    store.reset();
    store.dispatch({ type: "restore", layout: { saved_at: "", tabs: [SAVED.tabs[0]] } });
    const ref = placeholders(useSessionWorkspaceStore.getState().layout)[2].pending!.ref;
    expect(useSessionWorkspaceStore.getState().adopt([listing("sess_win", { pane_ref: ref })])).toEqual(["sess_win"]);
    const s = useSessionWorkspaceStore.getState().layout;
    expect(s.tabs).toHaveLength(1);
    expect(leaves(s.tabs[0].root).map((l) => l.token).includes("sess_win")).toBe(true);
    expect(placeholders(s)).toHaveLength(2);
  });

  it("a pane that left is not resurrected by a stale listing, but is adopted again at a later epoch", () => {
    const store = useSessionWorkspaceStore.getState();
    store.reset();
    store.adopt([listing("A")]);
    const paneA = leaves(useSessionWorkspaceStore.getState().layout.tabs[0].root)[0];
    useSessionWorkspaceStore.getState().dispatch({ type: "closePane", paneId: paneA.id });
    useSessionWorkspaceStore.getState().forget("A");
    expect(useSessionWorkspaceStore.getState().adopt([listing("A")])).toEqual([]);
    expect(useSessionWorkspaceStore.getState().adopt([listing("A", { attach_epoch: 3 })])).toEqual(["A"]);
  });
});
